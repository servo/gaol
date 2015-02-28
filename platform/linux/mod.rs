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
use profile::{self, Activate, OperationSupport, OperationSupportLevel, Profile};

pub mod misc;
pub mod namespace;
pub mod seccomp;

#[allow(missing_copy_implementations)]
pub struct Operation;

impl OperationSupport for profile::Operation {
    fn support(&self) -> OperationSupportLevel {
        match *self {
            profile::Operation::FileReadAll(_) |
            profile::Operation::FileReadMetadata(_) |
            profile::Operation::NetworkOutbound(AddressPattern::All) => {
                OperationSupportLevel::CanBeAllowed
            }
            profile::Operation::NetworkOutbound(AddressPattern::Tcp(_)) |
            profile::Operation::NetworkOutbound(AddressPattern::LocalSocket(_)) => {
                ProhibitionLevel::CannotBeAllowedPrecisely
            }
            profile::Operation::SystemInfoRead |
            profile::Operation::SystemSocket |
            profile::Operation::PlatformSpecific(_) => ProhibitionLevel::NeverAllowed,
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

