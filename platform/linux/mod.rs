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
use profile::{self, Activate, AddressPattern, OperationSupport, OperationSupportLevel, Profile};

pub mod misc;
pub mod namespace;
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

impl Activate for Profile {
    fn activate(&self) -> Result<(),()> {
        if namespace::activate(self).is_err() {
            return Err(())
        }
        if misc::activate().is_err() {
            return Err(())
        }
        match Filter::new(self).activate() {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

