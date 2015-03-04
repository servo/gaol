// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandbox profiles—lists of permitted operations.

use platform;

/// A sandbox profile, which specifies the set of operations that this process is allowed to
/// perform. Operations not in the list are implicitly prohibited.
///
/// If the process attempts to perform an operation in the list that this platform can prohibit
/// after the sandbox is entered via `activate()`, the operation will either fail or the process
/// will be immediately terminated. You can check whether an operation can be prohibited on this
/// platform with `Operation::prohibition_support()`.
///
/// All profiles implicitly prohibit *at least* the following operations. Future versions of `gaol`
/// may add operations to selectively allow these.
///
///    * Opening any file for writing.
///
///    * Creating new processes.
///
///    * Opening named pipes or System V IPC resources.
///
///    * Accessing System V semaphores.
///
///    * Sending signals to other processes.
///
///    * Tracing other processes.
///
///    * Accepting inbound network connections.
///
///    * Any operation that requires superuser privileges on the current operating system.
///
/// All profiles implicitly *allow* the following operations:
///
///    * All pure computation (user-mode CPU instructions that do not cause a context switch to
///      supervisor mode).
///
///    * Memory allocation (for example, via `brk` or anonymous `mmap` on Unix).
///
///    * Use of synchronization primitives (mutexes, condition variables).
///
///    * Changing memory protection and use policies: for example, marking pages non-writable or
///      informing the kernel that memory pages may be discarded. (It may be possible to restrict
///      this in future versions.)
///
///    * Spawning new threads.
///
///    * Responding to signals (e.g. `signal`, `sigaltstack`).
///
///    * Read, write, and memory map of already-opened file descriptors or handles.
///
///    * Determining how much has been sent on a file descriptor.
///
///    * Sending or receiving on already-opened sockets, including control messages on Unix.
///
///    * I/O multiplexing on already-opened sockets and/or file descriptors (`select`/`poll`).
///
///    * Opening and closing file descriptors and sockets (but not necessarily connecting them
///      to anything).
///
///    * Determining the user ID.
///
///    * Querying and altering thread scheduling options such as CPU affinity.
///
///    * Exiting the process.
///
/// Because of platform limitiations, patterns within one profile are not permitted to overlap; the
/// behavior is undefined if they do. For example, you may not allow metadata reads of the subpath
/// rooted at `/dev` while allowing full reads of `/dev/null`; you must instead allow full reads of
/// `/dev` or make the profile more restrictive.
#[derive(Clone, Debug)]
pub struct Profile {
    allowed_operations: Vec<Operation>,
}

/// An operation that this process is allowed to perform.
#[derive(Clone, Debug)]
pub enum Operation {
    /// All file-related reading operations may be performed on this file.
    FileReadAll(PathPattern),
    /// Metadata (for example, `stat` or `readlink`) of this file may be read.
    FileReadMetadata(PathPattern),
    /// Outbound network connections to the given address may be initiated.
    NetworkOutbound(AddressPattern),
    /// System information may be read (via `sysctl` on Unix).
    SystemInfoRead,
    /// Platform-specific operations.
    PlatformSpecific(platform::Operation),
}

/// Describes a path or paths on the filesystem.
#[derive(Clone, Debug)]
pub enum PathPattern {
    /// One specific path.
    Literal(Path),
    /// A directory and all of its contents, recursively.
    Subpath(Path),
}

/// Describes a network address.
#[derive(Clone, Debug)]
pub enum AddressPattern {
    /// All network addresses.
    All,
    /// TCP connections on the given port.
    Tcp(u16),
    /// A local socket at the given path (for example, a Unix socket).
    LocalSocket(Path),
}

impl Profile {
    /// Creates a new profile with the given set of allowed operations.
    ///
    /// If the operations cannot be allowed precisely on this platform, this returns an error. You
    /// can then inspect the operations via `OperationSupport::support()` to see which ones cannot
    /// be allowed and modify the set of allowed operations as necessary. We are deliberately
    /// strict here to reduce the probability of applications accidentally allowing operations due
    /// to platform limitations.
    pub fn new(allowed_operations: Vec<Operation>) -> Result<Profile,()> {
        if allowed_operations.iter().all(|operation| {
            match operation.support() {
                OperationSupportLevel::NeverAllowed | OperationSupportLevel::CanBeAllowed => true,
                OperationSupportLevel::CannotBeAllowedPrecisely |
                OperationSupportLevel::AlwaysAllowed => false,
            }
        }) {
            Ok(Profile {
                allowed_operations: allowed_operations,
            })
        } else {
            Err(())
        }
    }

    /// Returns the list of allowed operations.
    pub fn allowed_operations(&self) -> &[Operation] {
        self.allowed_operations.as_slice()
    }
}

/// How precisely an operation can be allowed on this platform.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OperationSupportLevel {
    /// This operation is never allowed on this platform.
    NeverAllowed,
    /// This operation can be precisely allowed on this platform.
    CanBeAllowed,
    /// This operation cannot be allowed precisely on this platform, but another set of operations
    /// allows it to be allowed on a more coarse-grained level. For example, on Linux, it is not
    /// possible to allow access to specific ports, but it is possible to allow network access
    /// entirely.
    CannotBeAllowedPrecisely,
    /// This operation is always allowed on this platform.
    AlwaysAllowed,
}

/// Allows operations to be queried to determine how precisely they can be allowed on this
/// platform.
pub trait OperationSupport {
    /// Returns an `OperationSupportLevel` describing how well this operation can be allowed on
    /// this platform.
    fn support(&self) -> OperationSupportLevel;
}

