// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use platform::linux::seccomp::Filter;
use platform::unix::process::Process;
use profile::{self, AddressPattern, OperationSupport, OperationSupportLevel, Profile};
use sandbox::{ChildSandboxMethods, Command, SandboxMethods};

use std::old_io::IoResult;

pub mod misc;
pub mod namespace;
pub mod process;
pub mod seccomp;

#[allow(missing_copy_implementations)]
#[derive(Clone, Debug)]
pub struct Operation;

impl OperationSupport for profile::Operation {
    fn support(&self) -> OperationSupportLevel {
        match *self {
            profile::Operation::FileReadAll(_) |
            profile::Operation::NetworkOutbound(AddressPattern::All) => {
                OperationSupportLevel::CanBeAllowed
            }
            profile::Operation::FileReadMetadata(_) |
            profile::Operation::NetworkOutbound(AddressPattern::Tcp(_)) |
            profile::Operation::NetworkOutbound(AddressPattern::LocalSocket(_)) => {
                OperationSupportLevel::CannotBeAllowedPrecisely
            }
            profile::Operation::SystemInfoRead |
            profile::Operation::PlatformSpecific(_) => OperationSupportLevel::NeverAllowed,
        }
    }
}

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

    fn start(&self, command: &mut Command) -> IoResult<Process> {
        namespace::start(&self.profile, command)
    }
}

pub struct ChildSandbox {
    profile: Profile,
}

impl ChildSandbox {
    pub fn new(profile: Profile) -> ChildSandbox {
        ChildSandbox {
            profile: profile,
        }
    }
}

impl ChildSandboxMethods for ChildSandbox {
    fn activate(&self) -> Result<(),()> {
        if namespace::activate(&self.profile).is_err() {
            return Err(())
        }
        if misc::activate().is_err() {
            return Err(())
        }
        match Filter::new(&self.profile).activate() {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

