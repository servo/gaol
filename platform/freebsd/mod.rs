// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandboxing on FreeBSD via Capsicum.

use platform::unix::process::Process;
use profile::{self, OperationSupport, OperationSupportLevel, Profile};
use sandbox::{ChildSandboxMethods, Command, SandboxMethods};

use libc::c_int;
use std::io;

impl OperationSupport for profile::Operation {
    fn support(&self) -> OperationSupportLevel {
        match *self {
            profile::Operation::SystemInfoRead =>
                OperationSupportLevel::AlwaysAllowed,
            _ => OperationSupportLevel::NeverAllowed
        }
    }
}

#[derive(Clone, Debug)]
pub enum Operation { }

pub struct Sandbox {
    profile: Profile,
}

impl Sandbox {
    pub fn new(profile: Profile) -> Sandbox {
        Sandbox {
            profile: profile,
        }
    }
}

impl SandboxMethods for Sandbox {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn start(&self, command: &mut Command) -> io::Result<Process> {
        command.env("GAOL_CHILD_PROCESS", "1").spawn()
    }
}

pub struct ChildSandbox {
}

impl ChildSandbox {
    pub fn new(_profile: Profile) -> ChildSandbox {
        ChildSandbox {
        }
    }
}

impl ChildSandboxMethods for ChildSandbox {
    fn activate(&self) -> Result<(),()> {
        if unsafe { cap_enter() } == 0 {
            Ok(())
        } else {
            error!("Failed to init sandbox");
            Err(())
        }
    }
}

extern {
    fn cap_enter() -> c_int;
}
