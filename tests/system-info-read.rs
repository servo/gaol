// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

#![allow(deprecated)]
#![feature(env, io, libc, std_misc)]

extern crate gaol;
extern crate libc;

use gaol::profile::{Activate, Operation, Profile};
use libc::{c_char, c_int, c_void, size_t};
use std::env;
use std::ffi::CString;
use std::iter;
use std::old_io::process::Command;
use std::ptr;

static SYSCTL_NAME: &'static str = "hw.ncpu";

#[cfg(target_os="macos")]
fn look_at_sysctl() {
    let sysctl_name = CString::from_slice(SYSCTL_NAME.as_bytes());
    let mut length = 0;
    unsafe {
        sysctlbyname(sysctl_name.as_ptr(), ptr::null_mut(), &mut length, ptr::null_mut(), 0);
        let mut value: Vec<_> = iter::repeat(0).take(length as usize).collect();
        assert!(sysctlbyname(sysctl_name.as_ptr(),
                             value.as_mut_ptr() as *mut c_void,
                             &mut length,
                             ptr::null_mut(),
                             0) == 0);
    }
}

#[ignore]
#[test]
#[cfg(target_os="macos")]
pub fn allowance_test() {
    Profile::new(vec![Operation::SystemInfoRead]).unwrap().activate().unwrap();
    look_at_sysctl();
}

#[ignore]
#[test]
#[cfg(target_os="macos")]
pub fn prohibition_test() {
    Profile::new(Vec::new()).unwrap().activate().unwrap();
    look_at_sysctl();
}

#[test]
#[cfg(target_os="macos")]
pub fn bootstrap() {
    let allowance_status = Command::new(env::current_exe().unwrap()).arg("--ignored")
                                                                    .arg("allowance_test")
                                                                    .status()
                                                                    .unwrap();
    assert!(allowance_status.success());

    let prohibition_status = Command::new(env::current_exe().unwrap()).arg("--ignored")
                                                                      .arg("prohibition_test")
                                                                      .status()
                                                                      .unwrap();
    assert!(!prohibition_status.success());
}

#[test]
#[cfg(not(target_os="macos"))]
pub fn bootstrap() {
    // Currently unsupported on non-Mac platforms.
}

#[cfg(target_os="macos")]
extern {
    fn sysctlbyname(name: *const c_char,
                    oldp: *mut c_void,
                    oldlenp: *mut size_t,
                    newp: *mut c_void,
                    newlen: size_t)
                    -> c_int;
}

