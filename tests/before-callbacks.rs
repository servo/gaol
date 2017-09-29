// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

extern crate gaol;
extern crate libc;

use gaol::profile::{Operation, PathPattern, Profile};
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
#[cfg(any(target_os="android", target_os="linux", target_os="macos"))]
use gaol::platform::unix::CommandExt;

use libc::ENOTTY;
use std::env;
use std::fs::metadata;
use std::io;
use std::path::PathBuf;

#[cfg(any(target_os="android", target_os="linux"))]
fn test_error_propagation() {
    fn return_err(_: &[i32]) -> io::Result<()> {
        // not a typewriter
        Err(io::Error::from_raw_os_error(ENOTTY))
    }

    fn profile() -> Profile {
        Profile::new(vec![]).unwrap()
    }
    let err =
        Sandbox::new(profile()).start(&mut Command::me().unwrap()
                                                      .arg("child")
                                                      .before_sandbox(return_err));
    match err {
        Err(e) => assert_eq!(e.raw_os_error(), Some(ENOTTY)),
        Ok(_) => panic!(),
    };

    let err =
        Sandbox::new(profile()).start(&mut Command::me().unwrap()
                                                      .arg("child")
                                                       .before_exec(return_err));
    match err {
        Err(e) => assert_eq!(e.raw_os_error(), Some(ENOTTY)),
        Ok(_) => panic!(),
    };
}

#[cfg(target_os="macos")]
fn test_error_propagation() {
    // TODO this doesn't work yet
}

#[cfg(any(target_os="android", target_os="linux", target_os="macos"))]
pub fn main() {
    fn profile() -> Profile {
        let exe = env::current_exe().unwrap();
        // Whitelist a bunch of directories that should let us launch this
        // binary OK. But not /tmp.
        Profile::new(vec![Operation::FileReadAll(PathPattern::Literal(exe)),
                          Operation::FileReadAll(PathPattern::Subpath(PathBuf::from("/usr"))),
                          Operation::FileReadAll(PathPattern::Subpath(PathBuf::from("/bin"))),
                          Operation::FileReadAll(PathPattern::Subpath(PathBuf::from("/lib64"))),
                          Operation::FileReadAll(PathPattern::Subpath(PathBuf::from("/lib"))),
                          Operation::CreateNewProcesses]).unwrap()
    }

    match env::args().skip(1).next() {
        Some(ref arg) if arg == "child" => return,
        _ => {}
    }

    fn do_before_sandbox(_: &[i32]) -> io::Result<()> {
        metadata("/tmp")?;
        Ok(())
    }

    #[cfg(any(target_os="android", target_os="linux"))]
    fn do_before_exec(_: &[i32]) -> io::Result<()> {
        ChildSandbox::new(profile()).activate().map_err(
            |_| io::Error::from_raw_os_error(ENOTTY))?;
        if metadata("/tmp").is_err() {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(ENOTTY))
        }
    }
    #[cfg(not(any(target_os="android", target_os="linux")))]
    fn do_before_exec(_: &[i32]) -> io::Result<()> { Ok(()) }

    let status =
        Sandbox::new(profile()).start(&mut Command::me().unwrap()
                                                        .arg("child")
                                                        .before_sandbox(do_before_sandbox)
                                                        .before_exec(do_before_exec))
                             .unwrap()
                             .wait()
                             .unwrap();
    assert!(status.success());

    test_error_propagation();
}

#[cfg(not(any(target_os="android", target_os="linux", target_os="macos")))]
pub fn main() {}

