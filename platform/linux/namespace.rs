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

use platform::linux;
use platform::unix::process::Process;
use platform::unix;
use profile::{Operation, PathPattern, Profile}; 
use sandbox::Command;

use libc::{self, c_char, c_int, c_ulong, c_void, gid_t, pid_t, uid_t};
use std::env;
use std::ffi::{AsOsStr, CString};
use std::iter;
use std::mem;
use std::old_io::{File, FilePermission, FileStat, FileType, IoError, IoResult};
use std::old_io::fs;
use std::ptr;

/// Creates a namespace and sets up a chroot jail.
pub fn activate(profile: &Profile) -> Result<(),c_int> {
    match try!(Namespace::new()).init() {
        Ok(()) => {}
        Err(_) => return Err(1),
    }

    try!(switch_to_unprivileged_user());

    let jail = try!(ChrootJail::new(profile));
    try!(jail.enter());
    drop_capabilities()
}

struct Namespace {
    parent_uid: uid_t,
    parent_gid: gid_t,
}

impl Namespace {
    fn new() -> Result<Namespace,c_int> {
        let parent_uid: uid_t =
            env::var("GAOL_PARENT_UID").unwrap().to_str().unwrap().parse().unwrap();
        let parent_gid: gid_t =
            env::var("GAOL_PARENT_GID").unwrap().to_str().unwrap().parse().unwrap();

        // If we got here, we're in the child.
        Ok(Namespace {
            parent_uid: parent_uid,
            parent_gid: parent_gid,
        })
    }

    fn init(&self) -> Result<(),IoError> {
        // See http://crbug.com/457362 for more information on this.
        try!(try!(File::create(&Path::new("/proc/self/setgroups"))).write_all(b"deny"));

        try!(try!(File::create(&Path::new("/proc/self/gid_map"))).write_all(
                format!("1 {} 1", self.parent_gid).as_bytes()));
        try!(File::create(&Path::new("/proc/self/uid_map"))).write_all(
            format!("1 {} 1", self.parent_uid).as_bytes())
    }
}

fn switch_to_unprivileged_user() -> Result<(),c_int> {
    unsafe {
        let result = setresgid(1, 1, 1);
        if result != 0 {
            return Err(result)
        }
        let result = setresuid(1, 1, 1);
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}

struct ChrootJail {
    directory: Path,
}

impl ChrootJail {
    fn new(profile: &Profile) -> Result<ChrootJail,c_int> {
        let prefix = CString::from_slice(b"/tmp/gaol.XXXXXX");
        let mut prefix: Vec<u8> = prefix.as_bytes_with_nul().iter().map(|x| *x).collect();
        unsafe {
            if mkdtemp(prefix.as_mut_ptr() as *mut c_char).is_null() {
                return Err(-1)
            }
        }
        let jail_dir = Path::new(&prefix[..prefix.len() - 1]);
        let jail = ChrootJail {
            directory: jail_dir,
        };

        let src = CString::from_slice(b"tmpfs");
        let dest = CString::from_slice(jail.directory
                                           .as_os_str()
                                           .to_str()
                                           .unwrap()
                                           .as_bytes());
        let tmpfs = CString::from_slice(b"tmpfs");
        let result = unsafe {
            mount(src.as_ptr(), dest.as_ptr(), tmpfs.as_ptr(), MS_NOATIME, ptr::null())
        };
        if result != 0 {
            return Err(result)
        }

        for operation in profile.allowed_operations().iter() {
            match *operation {
                Operation::FileReadAll(PathPattern::Literal(ref path)) |
                Operation::FileReadAll(PathPattern::Subpath(ref path)) => {
                    try!(jail.bind_mount(path))
                }
                _ => {}
            }
        }

        Ok(jail)
    }

    fn enter(&self) -> Result<(),c_int> {
        let directory = CString::from_slice(self.directory
                                                .as_os_str()
                                                .to_str()
                                                .unwrap()
                                                .as_bytes());
        let result = unsafe {
            chroot(directory.as_ptr())
        };
        if result != 0 {
            return Err(result)
        }

        match env::set_current_dir(&Path::new(".")) {
            Ok(_) => Ok(()),
            Err(_) => Err(-1),
        }
    }

    fn bind_mount(&self, source_path: &Path) -> Result<(),c_int> {
        // Create all intermediate directories.
        let mut destination_path = self.directory.clone();
        let mut components: Vec<Vec<u8>> =
            source_path.components().map(|bytes| bytes.iter().map(|x| *x).collect()).collect();
        let last_component = components.pop();
        for component in components.into_iter() {
            destination_path.push(component);
            if fs::mkdir(&destination_path, FilePermission::all()).is_err() {
                return Err(-1)
            }
        }

        // Create the mount file or directory.
        if let Some(last_component) = last_component {
            destination_path.push(last_component);
            match fs::stat(source_path) {
                Ok(FileStat {
                    kind: FileType::Directory,
                    ..
                }) => {
                    if fs::mkdir(&destination_path, FilePermission::all()).is_err() {
                        return Err(-1)
                    }
                }
                Ok(FileStat {
                    kind: _,
                    ..
                }) => {
                    if File::create(&destination_path).is_err() {
                        return Err(-1)
                    }
                }
                Err(_) => return Err(-1)
            }
        }

        // Create the bind mount.
        let source_path = CString::from_slice(source_path.as_os_str()
                                                         .to_str()
                                                         .unwrap()
                                                         .as_bytes());
        let destination_path = CString::from_slice(destination_path.as_os_str()
                                                                   .to_str()
                                                                   .unwrap()
                                                                   .as_bytes());
        let bind = CString::from_slice(b"bind");
        let result = unsafe {
            mount(source_path.as_ptr(),
                  destination_path.as_ptr(),
                  bind.as_ptr(),
                  MS_MGC_VAL | MS_BIND | MS_REC,
                  ptr::null_mut())
        };
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}

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

/// Spawns a child process in a new namespace.
pub fn start(profile: &Profile, command: &mut Command) -> IoResult<Process> {
    let (parent_uid, parent_gid) = unsafe {
        (libc::getuid(), libc::getgid())
    };

    let mut unshare_flags = CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;

    // If we don't allow network operations, create a network namespace.
    if !profile.allowed_operations().iter().any(|operation| {
        match *operation {
            Operation::NetworkOutbound(_) => true,
            _ => false,
        }
    }) {
        unshare_flags |= CLONE_NEWNET
    }

    command.env("GAOL_PARENT_UID", format!("{}", parent_uid).as_slice())
           .env("GAOL_PARENT_GID", format!("{}", parent_gid).as_slice());

    // Create a pipe so we can communicate the PID of our grandchild back.
    let mut pipe_fds = [0, 0];
    unsafe {
        assert!(libc::pipe(&mut pipe_fds[0]) == 0);

        // Fork so that we can unshare without removing our ability to create threads.
        match fork() {
            0 => {
                libc::close(pipe_fds[0]);

                /*if linux::process::sys_unshare(CLONE_NEWUSER | CLONE_NEWPID).is_err() {
                    abort()
                }*/

                // Fork again, to enter the PID namespace.
                match fork() {
                    0 => {
                        /*if linux::process::sys_unshare(unshare_flags).is_err() {
                            abort()
                        }*/
                        // Go ahead and start the command.
                        drop(unix::process::exec(command));
                        abort()
                    }
                    grandchild_pid => {
                        assert!(libc::write(pipe_fds[1],
                                            &grandchild_pid as *const pid_t as *const c_void,
                                            mem::size_of::<pid_t>() as u64) ==
                                                mem::size_of::<pid_t> as i64);
                        libc::exit(0);
                    }
                }
            }
            _ => {
                libc::close(pipe_fds[1]);

                // Retrieve our grandchild's PID.
                let mut grandchild_pid: pid_t = 0;
                assert!(libc::read(pipe_fds[0],
                                   &mut grandchild_pid as *mut i32 as *mut c_void,
                                   mem::size_of::<pid_t>() as u64) ==
                                    mem::size_of::<pid_t>() as i64);
                Ok(Process {
                    pid: grandchild_pid,
                })
            }
        }
    }
}

pub const CLONE_VM: c_int = 0x0000_0100;
pub const CLONE_FS: c_int = 0x0000_0200;
pub const CLONE_FILES: c_int = 0x0000_0400;
pub const CLONE_SIGHAND: c_int = 0x0000_0800;
pub const CLONE_THREAD: c_int = 0x0001_0000;
pub const CLONE_NEWNS: c_int = 0x0002_0000;
pub const CLONE_SYSVSEM: c_int = 0x0004_0000;
pub const CLONE_SETTLS: c_int = 0x0008_0000;
pub const CLONE_PARENT_SETTID: c_int = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: c_int = 0x0020_0000;
pub const CLONE_NEWUTS: c_int = 0x0400_0000;
pub const CLONE_NEWIPC: c_int = 0x0800_0000;
pub const CLONE_NEWUSER: c_int = 0x1000_0000;
pub const CLONE_NEWPID: c_int = 0x2000_0000;
pub const CLONE_NEWNET: c_int = 0x4000_0000;

const MS_NOATIME: c_ulong = 1024;
const MS_BIND: c_ulong = 4096;
const MS_REC: c_ulong = 16384;
const MS_MGC_VAL: c_ulong = 0xc0ed_0000;

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

const SIGCHLD: c_int = 17;

extern {
    fn abort() -> !;
    fn capset(hdrp: cap_user_header_t, datap: const_cap_user_data_t) -> c_int;
    fn chroot(path: *const c_char) -> c_int;
    fn fork() -> pid_t;
    fn mkdtemp(template: *mut c_char) -> *mut c_char;
    fn mount(source: *const c_char,
             target: *const c_char,
             filesystemtype: *const c_char,
             mountflags: c_ulong,
             data: *const c_void)
             -> c_int;
    fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> c_int;
    fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> c_int;
}

