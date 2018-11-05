// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

extern crate gaol;
extern crate libc;
extern crate num_cpus;

use gaol::profile::Profile;
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
use libc::c_int;
use std::env;
use std::thread;

#[cfg(target_os="linux")]
use gaol::platform::linux::seccomp::ALLOWED_SYSCALLS;

const MAX_SYSCALL: u32 = 400;

fn profile() -> Profile {
    Profile::new(Vec::new()).unwrap()
}

#[cfg(target_os="linux")]
fn test_syscall(number: c_int) {
    ChildSandbox::new(profile()).activate().unwrap();
    unsafe {
        syscall(number, -1, -1, -1, -1, -1, -1);
    }
}

#[cfg(target_os="linux")]
pub fn main() {
    if let Some(arg) = env::args().skip(1).next() {
        return test_syscall(arg.parse().unwrap())
    }

    let num_cpus = num_cpus::get() as u32;
    let handles = (0..num_cpus).into_iter().map(|index| {
        thread::spawn(move || {
            for syscall in 0..MAX_SYSCALL {
                if (syscall % num_cpus) != index {
                    continue
                }
                if ALLOWED_SYSCALLS.iter().any(|number| *number == syscall) {
                    continue
                }
                let arg = format!("{}", syscall);
                let status = Sandbox::new(profile()).start(&mut Command::me().unwrap().arg(&arg[..]))
                                                    .unwrap()
                                                    .wait()
                                                    .unwrap();
                assert!(!status.success());
            }
        })
    }).collect::<Vec<_>>();
    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(not(target_os="linux"))]
fn main() {}

#[cfg(target_os="linux")]
extern {
    fn syscall(number: c_int, ...) -> c_int;
}

