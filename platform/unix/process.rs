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

use crate::sandbox::Command;

use libc::{execve, fork, pid_t, waitpid, WEXITSTATUS, WIFEXITED, WTERMSIG};
use std::ffi::CString;
use std::io;
use std::ptr;
use std::str;

pub fn exec(command: &Command) -> io::Error {
    let mut args: Vec<_> = vec![command.module_path.as_ptr()];
    for arg in command.args.iter() {
        args.push(arg.as_ptr())
    }
    args.push(ptr::null());

    let env: Vec<_> = command
        .env
        .iter()
        .map(|(key, value)| {
            let entry = format!(
                "{}={}",
                str::from_utf8(key.to_bytes()).unwrap(),
                str::from_utf8(value.to_bytes()).unwrap()
            );
            CString::new(entry).unwrap()
        }).collect();
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
            pid => Ok(Process { pid }),
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
            let pid = unsafe { waitpid(-1, &mut stat, 0) };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid == self.pid {
                break;
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
