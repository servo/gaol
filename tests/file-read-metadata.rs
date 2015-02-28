// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

#![allow(deprecated)]
#![feature(collections, env, io, libc, os, path, rand, std_misc)]

extern crate gaol;
extern crate libc;

use gaol::profile::{Activate, Operation, PathPattern, Profile};
use libc::c_char;
use std::env;
use std::ffi::{AsOsStr, CString};
use std::old_io::fs::{File, PathExtensions};
use std::old_io::process::Command;
use std::rand::{self, Rng};

// A conservative overapproximation of `PATH_MAX` on all platforms.
const PATH_MAX: usize = 4096;

#[ignore]
#[test]
pub fn allowance_test() {
    let path = Path::new(env::var("GAOL_TEMP_FILE").unwrap().to_str().unwrap());
    Profile::new(vec![
        Operation::FileReadMetadata(PathPattern::Literal(path.clone())),
    ]).unwrap().activate().unwrap();
    drop(path.stat().unwrap())
}

#[ignore]
#[test]
pub fn prohibition_test() {
    let path = Path::new(env::var("GAOL_TEMP_FILE").unwrap().to_str().unwrap());
    Profile::new(vec![
        Operation::FileReadMetadata(PathPattern::Subpath(Path::new("/bogus")))
    ]).unwrap().activate().unwrap();
    drop(path.stat().unwrap())
}

#[test]
pub fn bootstrap() {
    // Need to use `realpath` here for Mac OS X, because the temporary directory is usually a
    // symlink.
    let mut temp_path = env::temp_dir();
    unsafe {
        let c_temp_path = CString::from_slice(temp_path.as_os_str().to_str().unwrap().as_bytes());
        let mut new_temp_path = [0u8; PATH_MAX];
        drop(realpath(c_temp_path.as_ptr(), new_temp_path.as_mut_ptr() as *mut c_char));
        temp_path = Path::new(&new_temp_path[..new_temp_path.position_elem(&0).unwrap()]);
    }

    let suffix: String = rand::thread_rng().gen_ascii_chars().take(6).collect();
    temp_path.push(format!("gaoltest.{}", suffix));
    File::create(&temp_path).unwrap().write_str("super secret\n").unwrap();

    let allowance_status = Command::new(env::current_exe().unwrap()).arg("--ignored")
                                                                    .arg("allowance_test")
                                                                    .env("GAOL_TEMP_FILE",
                                                                         temp_path.clone())
                                                                    .status()
                                                                    .unwrap();
    assert!(allowance_status.success());

    let prohibition_status = Command::new(env::current_exe().unwrap()).arg("--ignored")
                                                                      .arg("prohibition_test")
                                                                      .env("GAOL_TEMP_FILE",
                                                                           temp_path)
                                                                      .status()
                                                                      .unwrap();
    assert!(!prohibition_status.success());
}

extern {
    fn realpath(file_name: *const c_char, resolved_name: *mut c_char) -> *mut c_char;
}

