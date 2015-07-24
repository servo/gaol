// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandboxing on Linux via miscellaneous kernel features.

use platform::linux::seccomp;

use libc::{self, EPERM, c_int, mode_t};
use std::io;

pub fn activate() -> Result<(),c_int> {
    // Disable writing by setting the write limit to zero.
    let rlimit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe {
         setrlimit(RLIMIT_FSIZE, &rlimit)
    };
    if result != 0 {
        return Err(result)
    }

    // Set a restrictive `umask` so that even if files happened to get written it'd be hard to do
    // anything with them.
    unsafe {
        umask(0);
    }

    // Disable core dumps and debugging via `PTRACE_ATTACH`.
    let result = unsafe {
        seccomp::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    };
    if result != 0 {
        return Err(result)
    }

    // Enter a new session group. (This can fail with -EPERM if we're already the session leader,
    // which is OK.)
    unsafe {
        if libc::setsid() < 0 {
            let result = io::Error::last_os_error().raw_os_error().unwrap() as i32;
            if result != EPERM {
                return Err(result)
            }
        }
    }

    // Clear out the process environment.
    let result = unsafe {
        clearenv()
    };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct rlimit {
    rlim_cur: rlim_t,
    rlim_max: rlim_t,
}

#[allow(non_camel_case_types)]
type rlim_t = u64;

const PR_SET_DUMPABLE: c_int = 4;

const RLIMIT_FSIZE: c_int = 1;

extern {
    fn clearenv() -> c_int;
    fn setrlimit(resource: c_int, rlim: *const rlimit) -> c_int;
    fn umask(mask: mode_t) -> mode_t;
}

