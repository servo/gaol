// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(core, env, io, os, path)]

extern crate gaol;

use gaol::profile::{Activate, AddressPattern, Operation, OperationSupport, PathPattern, Profile};
use std::env;
use std::old_io::fs::File;

fn main() {
    let home = env::var("HOME").unwrap();
    let profile = Profile::new(vec![
        Operation::FileReadAll(PathPattern::Subpath(Path::new(home))),
        Operation::FileReadAll(PathPattern::Literal(Path::new("/etc"))),
        Operation::NetworkOutbound(AddressPattern::All),
        Operation::SystemInfoRead,
    ]).unwrap();
    for operation in profile.allowed_operations() {
        println!("{:?}: {:?}", operation, operation.support());
    }
    profile.activate().unwrap();

    match File::open(&Path::new("/bin/sh")) {
        Ok(_) => panic!("could access /bin/sh"),
        Err(error) => println!("{:?}", error),
    }
}

