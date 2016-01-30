// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

extern crate gaol;
extern crate libc;
extern crate rand;

use gaol::profile::{Operation, PathPattern, Profile};
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
use libc::c_char;
use rand::Rng;
use std::env;
use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;

// A conservative overapproximation of `PATH_MAX` on all platforms.
const PATH_MAX: usize = 4096;

fn allowance_profile(path: &PathBuf) -> Result<Profile,()> {
    Profile::new(vec![
        Operation::FileReadMetadata(PathPattern::Literal(path.clone())),
    ])
}

fn prohibition_profile() -> Result<Profile,()> {
    Profile::new(vec![
        Operation::FileReadMetadata(PathPattern::Subpath(PathBuf::from("/bogus")))
    ])
}

fn allowance_test() {
    let path = PathBuf::from(env::var("GAOL_TEMP_FILE").unwrap());
    if ChildSandbox::new(allowance_profile(&path).unwrap()).activate().is_ok() {
        drop(fs::metadata(path).unwrap())
    }
}

fn prohibition_test() {
    let path = PathBuf::from(env::var("GAOL_TEMP_FILE").unwrap());
    ChildSandbox::new(prohibition_profile().unwrap()).activate().unwrap();
    drop(fs::metadata(path).unwrap())
}

pub fn main() {
    match env::args().skip(1).next() {
        Some(ref arg) if arg == "allowance_test" => return allowance_test(),
        Some(ref arg) if arg == "prohibition_test" => return prohibition_test(),
        _ => {}
    }

    // Need to use `realpath` here for Mac OS X, because the temporary directory is usually a
    // symlink.
    let mut temp_path = env::temp_dir();
    unsafe {
        let c_temp_path =
            CString::new(temp_path.as_os_str().to_str().unwrap().as_bytes()).unwrap();
        let mut new_temp_path = [0u8; PATH_MAX];
        drop(realpath(c_temp_path.as_ptr(), new_temp_path.as_mut_ptr() as *mut c_char));
        let pos = new_temp_path.iter().position(|&x| x == 0).unwrap();
        temp_path = PathBuf::from(OsStr::from_bytes(&new_temp_path[..pos]));
    }

    let suffix: String = rand::thread_rng().gen_ascii_chars().take(6).collect();
    temp_path.push(format!("gaoltest.{}", suffix));
    File::create(&temp_path).unwrap().write_all(b"super secret\n").unwrap();

    if let Ok(profile) = allowance_profile(&temp_path) {
        let allowance_status =
            Sandbox::new(profile).start(&mut Command::me().unwrap()
                                                          .arg("allowance_test")
                                                          .env("GAOL_TEMP_FILE",
                                                               temp_path.clone()))
                                 .unwrap()
                                 .wait()
                                 .unwrap();
        assert!(allowance_status.success());
    }

    if let Ok(profile) = prohibition_profile() {
        let prohibition_status =
            Sandbox::new(profile).start(Command::me().unwrap()
                                                     .arg("prohibition_test")
                                                     .env("GAOL_TEMP_FILE", temp_path.clone()))
                                 .unwrap()
                                 .wait()
                                 .unwrap();
        assert!(!prohibition_status.success());
    }
}

extern {
    fn realpath(file_name: *const c_char, resolved_name: *mut c_char) -> *mut c_char;
}

