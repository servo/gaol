// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io;
use std::os::unix::io::RawFd;

pub mod process;

use sandbox::Command;

pub trait CommandExt {
    /// Schedules a closure to be run after forking but before any sandbox
    /// controls are applied. This may not be the final process that will exec.
    /// This lets you set up subprocess state that must be initialized before
    /// dropping privileges, without disturbing the parent process.
    ///
    /// The closure is allowed to return an I/O error whose OS error code will
    /// be communicated back to the parent and returned as an error from when
    /// the start was requested.
    ///
    /// Multiple closures can be registered and they will be called in order of
    /// their registration. If a closure returns `Err` then no further closures
    /// will be called and the start operation will immediately return with a
    /// failure.
    /// TODO on Mac, errors are not yet propagated to start().
    ///
    /// # Notes
    ///
    /// This closure will be run in the context of the child process after a
    /// `fork`. This primarily means that any modificatons made to memory on
    /// behalf of this closure will **not** be visible to the parent process.
    /// This is often a very constrained environment where normal operations
    /// like `malloc` or acquiring a mutex are not guaranteed to work (due to
    /// other threads perhaps still running when the `fork` was run).
    ///
    /// Avoid closing any file descriptors in the passed-in list. These are
    /// O_CLOEXEC so will automatically close when the command runs.
    fn before_sandbox<F>(&mut self, f: F) -> &mut Command
        where F: FnMut(&[RawFd]) -> io::Result<()> + Send + Sync + 'static;
    /// Schedules a closure to be run after any pre-exec sandbox controls are
    /// but before exec, in the process that will exec. On Linux, this closure
    /// can call ChildSandbox::activate(), letting you sandbox a foreign
    /// executable and then perform process setup steps that must be performed
    /// after the sandbox is activated.
    ///
    /// The closure is allowed to return an I/O error whose OS error code will
    /// be communicated back to the parent and returned as an error from when
    /// the start was requested.
    ///
    /// Multiple closures can be registered and they will be called in order of
    /// their registration. If a closure returns `Err` then no further closures
    /// will be called and the start operation will immediately return with a
    /// failure.
    /// TODO on Mac, errors are not yet propagated to start().
    ///
    /// # Notes
    ///
    /// This closure will be run in the context of the child process after a
    /// `fork`. This primarily means that any modificatons made to memory on
    /// behalf of this closure will **not** be visible to the parent process.
    /// This is often a very constrained environment where normal operations
    /// like `malloc` or acquiring a mutex are not guaranteed to work (due to
    /// other threads perhaps still running when the `fork` was run).
    ///
    /// Avoid closing any file descriptors in the passed-in list. These are
    /// O_CLOEXEC so will automatically close when the command runs.
    fn before_exec<F>(&mut self, f: F) -> &mut Command
        where F: FnMut(&[RawFd]) -> io::Result<()> + Send + Sync + 'static;
}

pub struct CommandInner {
    before_sandbox_closures: Vec<Box<FnMut(&[RawFd]) -> io::Result<()> + Send + Sync + 'static>>,
    before_exec_closures: Vec<Box<FnMut(&[RawFd]) -> io::Result<()> + Send + Sync + 'static>>,
}

impl CommandInner {
    pub fn new() -> CommandInner {
        CommandInner {
            before_sandbox_closures: Vec::new(),
            before_exec_closures: Vec::new(),
        }
    }

    pub fn before_sandbox(&mut self, preserve_fds: &[RawFd]) -> io::Result<()> {
        for c in self.before_sandbox_closures.iter_mut() {
            c(preserve_fds)?;
        }
        self.before_sandbox_closures.clear();
        Ok(())
    }

    pub fn before_exec(&mut self, preserve_fds: &[RawFd]) -> io::Result<()> {
        for c in self.before_exec_closures.iter_mut() {
            c(preserve_fds)?;
        }
        self.before_exec_closures.clear();
        Ok(())
    }
}

impl CommandExt for Command {
    fn before_sandbox<F>(&mut self, f: F) -> &mut Command
        where F: FnMut(&[RawFd]) -> io::Result<()> + Send + Sync + 'static {
        self.inner.before_sandbox_closures.push(Box::new(f));
        self
    }
    fn before_exec<F>(&mut self, f: F) -> &mut Command
        where F: FnMut(&[RawFd]) -> io::Result<()> + Send + Sync + 'static {
        self.inner.before_exec_closures.push(Box::new(f));
        self
    }
}
