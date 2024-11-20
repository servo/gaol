// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod profile;
pub mod sandbox;

pub mod platform {
    #[cfg(any(target_os="android", target_os="linux"))]
    pub use self::linux::{ChildSandbox, Operation, Sandbox};
    #[cfg(target_os="macos")]
    pub use self::macos::{ChildSandbox, Operation, Sandbox};
    #[cfg(target_os="freebsd")]
    pub use self::freebsd::{ChildSandbox, Operation, Sandbox};
    #[cfg(any(target_os="android", target_os="linux", target_os="macos", target_os="freebsd"))]
    pub use self::unix::process::{self, Process};

    #[cfg(any(target_os="android", target_os="linux"))]
    pub mod linux;
    #[cfg(target_os="macos")]
    pub mod macos;
    #[cfg(target_os="freebsd")]
    pub mod freebsd;
    #[cfg(any(target_os="android", target_os="linux", target_os="macos", target_os="freebsd"))]
    pub mod unix;
}

