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
use profile::{self, Activate, Profile, ProhibitionLevel, ProhibitionSupport};

pub mod misc;
pub mod namespace;
pub mod seccomp;

#[allow(missing_copy_implementations)]
pub struct Operation;

impl ProhibitionSupport for profile::Operation {
    fn prohibition_support(&self) -> ProhibitionLevel {
        match *self {
            profile::Operation::FileReadAll(_) |
            profile::Operation::FileReadMetadata(_) => ProhibitionLevel::Precise,
            profile::Operation::NetworkOutbound(_) => ProhibitionLevel::Coarse,
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

