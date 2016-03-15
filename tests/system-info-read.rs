// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

extern crate gaol;
extern crate libc;

use gaol::profile::{Operation, Profile};
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
use libc::{c_char, c_int, c_void, size_t};
use std::env;
use std::ffi::CString;
use std::iter;
use std::ptr;

static SYSCTL_NAME: &'static str = "hw.ncpu";

#[cfg(target_os="macos")]
fn look_at_sysctl() {
    let sysctl_name = CString::new(SYSCTL_NAME.as_bytes().to_vec()).unwrap();
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

fn allowance_profile() -> Profile {
    Profile::new(vec![Operation::SystemInfoRead]).unwrap()
}

fn prohibition_profile() -> Profile {
    Profile::new(Vec::new()).unwrap()
}

#[cfg(target_os="macos")]
pub fn allowance_test() {
    ChildSandbox::new(allowance_profile()).activate().unwrap();
    look_at_sysctl();
}

#[cfg(target_os="macos")]
pub fn prohibition_test() {
    ChildSandbox::new(prohibition_profile()).activate().unwrap();
    look_at_sysctl();
}

#[cfg(target_os="macos")]
pub fn main() {
    match env::args().skip(1).next() {
        Some(ref arg) if arg == "allowance_test" => return allowance_test(),
        Some(ref arg) if arg == "prohibition_test" => return prohibition_test(),
        _ => {}
    }

    let allowance_status =
        Sandbox::new(allowance_profile()).start(&mut Command::me().unwrap().arg("allowance_test"))
                                         .unwrap()
                                         .wait()
                                         .unwrap();
    assert!(allowance_status.success());

    let prohibition_status =
        Sandbox::new(prohibition_profile()).start(&mut Command::me().unwrap()
                                                                    .arg("prohibition_test"))
                                           .unwrap()
                                           .wait()
                                           .unwrap();
    assert!(!prohibition_status.success());
}

#[cfg(not(target_os="macos"))]
pub fn main() {
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

