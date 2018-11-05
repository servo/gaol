// Any copyright is dedicated to the Public Domain.
// http://creativecommons.org/publicdomain/zero/1.0/

extern crate gaol;

//use gaol::profile::{AddressPattern, Operation, OperationSupport, OperationSupportLevel};
//use gaol::profile::{PathPattern, Profile};
use gaol::profile::Profile;
use gaol::sandbox::{ChildSandbox, ChildSandboxMethods, Command, Sandbox, SandboxMethods};
use std::env;
use std::io;
use std::io::{Read, Write};

fn main() {
    match env::args().skip(1).next() {
        Some(ref arg) if arg == "child" => {
            // This is the child process.
            ChildSandbox::new(Profile::new(vec![]).unwrap()).activate().unwrap();
	    
	    let mut buf = vec![0];
	    io::stdin().read_exact(&mut buf[..]).unwrap();
	    assert_eq!(buf, b"A");

	    io::stdout().write_all(b"B").unwrap();
	    io::stdout().flush().unwrap();
        }
        _ => {
            // This is the parent process.
            let mut command = Command::me().unwrap();
            let mut cmd = Sandbox::new(Profile::new(vec![]).unwrap()).start(command.arg("child")).unwrap();

	    cmd.stdin.write_all(b"A").unwrap();
	    cmd.stdin.flush().unwrap();

	    let mut buf = vec![0];
	    cmd.stdout.read_exact(&mut buf[..]).unwrap();
	    assert_eq!(buf, b"B");

	    cmd.wait().unwrap();
        }
    }
}

