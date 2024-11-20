// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandboxing on Linux via namespaces.

use crate::platform::unix;
use crate::platform::unix::process::Process;
use crate::profile::{Operation, PathPattern, Profile};
use crate::sandbox::Command;

use libc::{self, c_char, c_int, c_void, gid_t, pid_t, size_t, ssize_t, uid_t};
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::iter;
use std::mem;
use std::os::unix::prelude::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

/// Creates a namespace and sets up a chroot jail.
pub fn activate(profile: &Profile) -> Result<(), c_int> {
    let jail = ChrootJail::new(profile)?;
    jail.enter()?;
    drop_capabilities()
}

/// A `chroot` jail with a restricted view of the filesystem inside it.
struct ChrootJail {
    directory: PathBuf,
}

impl ChrootJail {
    /// Creates a new `chroot` jail.
    fn new(profile: &Profile) -> Result<ChrootJail,c_int> {
        let prefix = CString::new("/tmp/gaol.XXXXXX").unwrap();
        let mut prefix: Vec<u8> = prefix.as_bytes_with_nul().iter().map(|x| *x).collect();
        unsafe {
            if libc::mkdtemp(prefix.as_mut_ptr() as *mut c_char).is_null() {
                return Err(-1)
            }
        }
        let jail_dir = PathBuf::from(OsStr::from_bytes(&prefix[..prefix.len() - 1]));
        let jail = ChrootJail {
            directory: jail_dir,
        };

        let dest = CString::new(jail.directory
                                    .as_os_str()
                                    .to_str()
                                    .unwrap()
                                    .as_bytes()).unwrap();
        let tmpfs = CString::new("tmpfs").unwrap();
        let result = unsafe {
            libc::mount(tmpfs.as_ptr(),
                        dest.as_ptr(),
                        tmpfs.as_ptr(),
                        libc::MS_NOATIME | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
                        ptr::null())
        };
        if result != 0 {
            return Err(result)
        }

        for operation in profile.allowed_operations().iter() {
            match *operation {
                Operation::FileReadAll(PathPattern::Literal(ref path)) |
                Operation::FileReadAll(PathPattern::Subpath(ref path)) => {
                    jail.bind_mount(path)?;
                }
                _ => {}
            }
        }

        Ok(jail)
    }

    /// Enters the `chroot` jail.
    fn enter(&self) -> Result<(),c_int> {
        let directory = CString::new(self.directory
                                         .as_os_str()
                                         .to_str()
                                         .unwrap()
                                         .as_bytes()).unwrap();
        let result = unsafe {
            libc::chroot(directory.as_ptr())
        };
        if result != 0 {
            return Err(result)
        }

        match env::set_current_dir(&Path::new(".")) {
            Ok(_) => Ok(()),
            Err(_) => Err(-1),
        }
    }

    /// Bind mounts a path into our chroot jail.
    fn bind_mount(&self, source_path: &Path) -> Result<(),c_int> {
        // Create all intermediate directories.
        let mut destination_path = self.directory.clone();
        let mut components: Vec<OsString> =
            source_path.components().skip(1)
                                    .map(|component| component.as_os_str().to_os_string())
                                    .collect();
        let last_component = components.pop();
        for component in components.into_iter() {
            destination_path.push(component);
            if fs::create_dir(&destination_path).is_err() {
                return Err(-1)
            }
        }

        // Create the mount file or directory.
        if let Some(last_component) = last_component {
            destination_path.push(last_component);
            match fs::metadata(source_path) {
                Ok(ref metadata) if metadata.is_dir() => {
                    if fs::create_dir(&destination_path).is_err() {
                        return Err(-1)
                    }
                }
                Ok(_) => {
                    if File::create(&destination_path).is_err() {
                        return Err(-1)
                    }
                }
                Err(_) => {
                    // The source directory didn't exist. Just don't create the bind mount.
                    return Ok(())
                }
            }
        }

        // Create the bind mount.
        let source_path = CString::new(source_path.as_os_str()
                                                  .to_str()
                                                  .unwrap()
                                                  .as_bytes()).unwrap();
        let destination_path = CString::new(destination_path.as_os_str()
                                                            .to_str()
                                                            .unwrap()
                                                            .as_bytes()).unwrap();
        let bind = CString::new("bind").unwrap();
        let result = unsafe {
            libc::mount(source_path.as_ptr(),
                  destination_path.as_ptr(),
                  bind.as_ptr(),
                  libc::MS_MGC_VAL | libc::MS_BIND | libc::MS_REC,
                  ptr::null_mut())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}

/// Removes fake-superuser capabilities. This removes our ability to mess with the filesystem view
/// we've set up.
fn drop_capabilities() -> Result<(),c_int> {
    let capability_data: Vec<_> = iter::repeat(__user_cap_data_struct {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }).take(_LINUX_CAPABILITY_U32S_3 as usize).collect();
    let result = unsafe {
        capset(&__user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        }, capability_data.as_ptr())
    };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

/// Sets up the user and PID namespaces.
unsafe fn prepare_user_and_pid_namespaces(parent_uid: uid_t, parent_gid: gid_t) -> io::Result<()> {
    // Enter the main user and PID namespaces.
    assert_eq!(libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID), 0);

    // See http://crbug.com/457362 for more information on this.
    File::create(&Path::new("/proc/self/setgroups"))?.write_all(b"deny")?;

    let gid_contents = format!("0 {} 1", parent_gid);
    File::create(&Path::new("/proc/self/gid_map"))?.write_all(gid_contents.as_bytes())?;

    let uid_contents = format!("0 {} 1", parent_uid);
    File::create(&Path::new("/proc/self/uid_map"))?.write_all(uid_contents.as_bytes())?;

    Ok(())
}

/// Spawns a child process in a new namespace.
///
/// This function is quite tricky. Hic sunt dracones!
pub fn start(profile: &Profile, command: &mut Command) -> io::Result<Process> {
    // Store our root namespace UID and GID because they're going to change once we enter a user
    // namespace.
    let (parent_uid, parent_gid) = unsafe {
        (libc::getuid(), libc::getgid())
    };

    // Always create an IPC namespace, a mount namespace, and a UTS namespace. Additionally, if we
    // aren't allowing network operations, create a network namespace.
    let mut unshare_flags = libc::CLONE_NEWIPC | libc::CLONE_NEWNS | libc::CLONE_NEWUTS;
    if !profile.allowed_operations().iter().any(|operation| {
        match *operation {
            Operation::NetworkOutbound(_) => true,
            _ => false,
        }
    }) {
        unshare_flags |= libc::CLONE_NEWNET
    }

    unsafe {
        // Create a pipe so we can communicate the PID of our grandchild back.
        let mut pipe_fds = [0, 0];
        assert_eq!(libc::pipe(&mut pipe_fds[0]), 0);

        // Set this `prctl` flag so that we can wait on our grandchild. (Otherwise it'll be
        // reparented to init.)
        assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0), 0);

        // Fork so that we can unshare without removing our ability to create threads.
        if libc::fork() == 0 {
            // Close the reading end of the pipe.
            libc::close(pipe_fds[0]);

            // Set up our user and PID namespaces. The PID namespace won't actually come into
            // effect until the next fork(), because PIDs are immutable.
            prepare_user_and_pid_namespaces(parent_uid, parent_gid)?;

            // Fork again, to enter the PID namespace.
            match libc::fork() {
                0 => {
                    // Enter the auxiliary namespaces.
                    assert_eq!(libc::unshare(unshare_flags), 0);

                    // Go ahead and start the command.
                    drop(unix::process::exec(command));
                    libc::abort()
                }
                grandchild_pid => {
                    // Send the PID of our child up to our parent and exit.
                    assert_eq!(
                        libc::write(
                            pipe_fds[1],
                            &grandchild_pid as *const pid_t as *const c_void,
                            mem::size_of::<pid_t>() as size_t
                        ),
                        mem::size_of::<pid_t>() as ssize_t
                    );
                    libc::exit(0);
                }
            }
        }

        // Grandparent execution continues here. First, close the writing end of the pipe.
        libc::close(pipe_fds[1]);

        // Retrieve our grandchild's PID.
        let mut grandchild_pid: pid_t = 0;
        assert_eq!(
            libc::read(
                pipe_fds[0],
                &mut grandchild_pid as *mut i32 as *mut c_void,
                mem::size_of::<pid_t>() as size_t
            ),
            mem::size_of::<pid_t>() as ssize_t
        );

        Ok(Process {
            pid: grandchild_pid,
        })
    }
}
#[repr(C)]
#[allow(non_camel_case_types)]
struct __user_cap_header_struct {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
struct __user_cap_data_struct {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[allow(non_camel_case_types)]
type cap_user_header_t = *const __user_cap_header_struct;

#[allow(non_camel_case_types)]
type const_cap_user_data_t = *const __user_cap_data_struct;

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const _LINUX_CAPABILITY_U32S_3: u32 = 2;
extern {
    fn capset(hdrp: cap_user_header_t, datap: const_cap_user_data_t) -> c_int;
}
