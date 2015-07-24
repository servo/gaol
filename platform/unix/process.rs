// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Child process management on POSIX systems.

use sandbox::Command;

use libc::{c_char, c_int, pid_t};
use std::ffi::CString;
use std::io;
use std::ptr;

pub fn exec(command: &Command) -> io::Error {
    let mut args: Vec<_> = vec![command.module_path.as_ptr()];
    for arg in command.args.iter() {
        args.push(arg.as_ptr())
    }
    args.push(ptr::null());

    let env: Vec<_> =
        command.env.iter().map(|(key, value)| {
            format!("{}={}",
                    String::from_utf8(key.to_bytes().to_vec()).unwrap(),
                    String::from_utf8(value.to_bytes().to_vec()).unwrap())
        }).collect();
    let env: Vec<_> = env.iter()
                         .map(|entry| CString::new(entry.as_bytes().to_vec()).unwrap())
                         .collect();
    let mut env: Vec<_> = env.iter().map(|entry| entry.as_ptr()).collect();
    env.push(ptr::null());

    unsafe {
        execve(command.module_path.as_ptr(), args.as_ptr(), env.as_ptr());
    }

    io::Error::last_os_error()
}

pub fn spawn(command: &Command) -> io::Result<Process> {
    unsafe {
        match fork() {
            0 => {
                drop(exec(command));
                panic!()
            }
            pid => {
                Ok(Process {
                    pid: pid,
                })
            }
        }
    }
}

#[allow(missing_copy_implementations)]
pub struct Process {
    pub pid: pid_t,
}

impl Process {
    pub fn wait(&self) -> io::Result<ExitStatus> {
        let mut stat = 0;
        loop {
            let pid = unsafe {
                waitpid(-1, &mut stat, 0)
            };
            if pid < 0 {
                return Err(io::Error::last_os_error())
            }
            if pid == self.pid {
                break
            }
        }

        if WIFEXITED(stat) {
            Ok(ExitStatus::Code(WEXITSTATUS(stat) as i32))
        } else {
            Ok(ExitStatus::Signal(WTERMSIG(stat) as i32))
        }
    }
}

pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

impl ExitStatus {
    #[inline]
    pub fn success(&self) -> bool {
        match *self {
            ExitStatus::Code(0) => true,
            _ => false,
        }
    }
}

#[allow(non_snake_case)]
fn WIFEXITED(stat: c_int) -> bool {
    (stat & 0o177) == 0
}

#[allow(non_snake_case)]
fn WEXITSTATUS(stat: c_int) -> u8 {
    (stat >> 8) as u8
}

#[allow(non_snake_case)]
fn WTERMSIG(stat: c_int) -> u8 {
    (stat & 0o177) as u8
}

extern {
    fn fork() -> pid_t;
    fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char)
              -> c_int;
    fn waitpid(pid: pid_t, stat_loc: *mut c_int, options: c_int) -> pid_t;
}

