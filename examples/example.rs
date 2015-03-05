// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(env, io, path)]

extern crate gaol;

use gaol::profile::{AddressPattern, Operation, OperationSupport, OperationSupportLevel};
use gaol::profile::{PathPattern, Profile};
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
use std::env;
use std::old_io::fs::File;

// Create the sandbox profile.
fn profile() -> Profile {
    // Set up the list of desired operations.
    let mut operations = vec![
        Operation::FileReadAll(PathPattern::Subpath(Path::new("/lib"))),
        Operation::FileReadAll(PathPattern::Literal(Path::new("/etc"))),
        Operation::NetworkOutbound(AddressPattern::All),
        Operation::SystemInfoRead,
    ];

    // Remove operations not supported by this OS. (Otherwise the creation of the profile will
    // fail.)
    operations.retain(|operation| {
        println!("{:?}: {:?}", operation, operation.support());
        match operation.support() {
            OperationSupportLevel::NeverAllowed | OperationSupportLevel::CanBeAllowed => true,
            _ => false,
        }
    });

    Profile::new(operations).unwrap()
}

fn main() {
    match env::args().skip(1).next() {
        Some(ref arg) if arg == "child" => {
            // This is the child process.
            ChildSandbox::new(profile()).activate().unwrap();
            match File::open(&Path::new("/bin/sh")) {
                Err(error) => println!("{:?}", error),
                Ok(_) => panic!("could access /bin/sh"),
            }
        }
        _ => {
            // This is the parent process.
            let mut command = Command::me().unwrap();
            Sandbox::new(profile()).start(command.arg("child")).unwrap().wait().unwrap();
        }
    }
}

