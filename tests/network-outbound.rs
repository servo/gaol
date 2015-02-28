// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

#![allow(deprecated)]
#![feature(env, io)]

extern crate gaol;

use gaol::profile::{Activate, AddressPattern, Operation, Profile};
use std::env;
use std::old_io::{Listener, TcpListener, TcpStream};
use std::old_io::process::Command;

static ADDRESS: &'static str = "127.0.0.1:7357";

fn allowance_test() {
    Profile::new(vec![
        Operation::NetworkOutbound(AddressPattern::All)
    ]).unwrap().activate().unwrap();
    drop(TcpStream::connect(ADDRESS).unwrap())
}

fn prohibition_test() {
    Profile::new(Vec::new()).unwrap().activate().unwrap();
    drop(TcpStream::connect(ADDRESS).unwrap())
}

pub fn main() {
    match env::args().skip(1).next() {
        Some(ref arg) if arg == "allowance_test" => return allowance_test(),
        Some(ref arg) if arg == "prohibition_test" => return prohibition_test(),
        _ => {}
    }

    let listener = TcpListener::bind(ADDRESS).unwrap();
    let _acceptor = listener.listen();

    let allowance_status = Command::new(env::current_exe().unwrap()).arg("allowance_test")
                                                                    .status()
                                                                    .unwrap();
    assert!(allowance_status.success());

    let prohibition_status = Command::new(env::current_exe().unwrap()).arg("prohibition_test")
                                                                      .status()
                                                                      .unwrap();
    assert!(!prohibition_status.success());
}

