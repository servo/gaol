// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Sandboxing on Mac OS X via Seatbelt (`sandboxd`).

use profile::{self, Activate, AddressPattern, PathPattern, Profile, ProhibitionLevel};
use profile::{ProhibitionSupport};

use libc::{c_char, c_int};
use std::ffi::{AsOsStr, CString};
use std::old_io::MemWriter;
use std::ptr;
use std::str;

static SANDBOX_PROFILE_PROLOGUE: &'static [u8] = b"
(version 1)
(deny default)
";

impl ProhibitionSupport for profile::Operation {
    fn prohibition_support(&self) -> ProhibitionLevel {
        match *self {
            profile::Operation::FileReadAll(_) |
            profile::Operation::FileReadMetadata(_) |
            profile::Operation::NetworkOutbound(_) |
            profile::Operation::SystemInfoRead |
            profile::Operation::SystemSocket |
            profile::Operation::PlatformSpecific(_) => ProhibitionLevel::Precise,
        }
    }
}

/// Mac OS X-specific operations.
#[derive(Clone, Debug)]
pub enum Operation {
    /// Lookups to the given Mach service are allowed.
    MachLookup(Vec<u8>),
}

impl Activate for Profile {
    fn activate(&self) -> Result<(),()> {
        let mut sandbox_profile = MemWriter::new();
        sandbox_profile.write_all(SANDBOX_PROFILE_PROLOGUE).unwrap();
        for operation in self.allowed_operations().iter() {
            match *operation {
                profile::Operation::FileReadAll(ref file_pattern) => {
                    sandbox_profile.write_all(b"(allow file-read* ").unwrap();
                    write_file_pattern(&mut sandbox_profile, file_pattern);
                    sandbox_profile.write_all(b")\n").unwrap();
                }
                profile::Operation::FileReadMetadata(ref file_pattern) => {
                    sandbox_profile.write_all(b"(allow file-read-metadata ").unwrap();
                    write_file_pattern(&mut sandbox_profile, file_pattern);
                    sandbox_profile.write_all(b")\n").unwrap();
                }
                profile::Operation::NetworkOutbound(ref address_pattern) => {
                    sandbox_profile.write_all(b"(allow network-outbound (").unwrap();
                    match *address_pattern {
                        AddressPattern::Tcp(port) => {
                            write!(&mut sandbox_profile, "remote tcp \"*:{}\"", port).unwrap()
                        }
                        AddressPattern::LocalSocket(ref path) => {
                            sandbox_profile.write_all(b"literal ").unwrap();
                            write_path(&mut sandbox_profile, path)
                        }
                    }
                    sandbox_profile.write_all(b"))\n").unwrap();
                }
                profile::Operation::SystemInfoRead => {
                    sandbox_profile.write_all(b"(allow sysctl-read)\n").unwrap()
                }
                profile::Operation::SystemSocket => {
                    sandbox_profile.write_all(b"(allow system-socket)\n").unwrap()
                }
                profile::Operation::PlatformSpecific(Operation::MachLookup(ref service_name)) => {
                    sandbox_profile.write_all(b"(allow mach_lookup ").unwrap();
                    write_quoted_string(&mut sandbox_profile, service_name.as_slice());
                    sandbox_profile.write_all(b")\n").unwrap();
                }
            }
        }

        debug!("{}", str::from_utf8(sandbox_profile.get_ref()).unwrap());

        let profile = CString::from_slice(sandbox_profile.get_ref());
        let mut err = ptr::null_mut();
        unsafe {
            if sandbox_init(profile.as_ptr(), 0, &mut err) == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}

fn write_file_pattern(sandbox_profile: &mut MemWriter, path_pattern: &PathPattern) {
    match *path_pattern {
        PathPattern::Literal(ref path) => {
            sandbox_profile.write_all(b"(literal ").unwrap();
            write_path(sandbox_profile, path)
        }
        PathPattern::Subpath(ref path) => {
            sandbox_profile.write_all(b"(subpath ").unwrap();
            write_path(sandbox_profile, path)
        }
    }
    sandbox_profile.write_all(b")").unwrap()
}

fn write_path(sandbox_profile: &mut MemWriter, path: &Path) {
    write_quoted_string(sandbox_profile, path.as_os_str().to_str().unwrap().as_bytes())
}

fn write_quoted_string(sandbox_profile: &mut MemWriter, string: &[u8]) {
    sandbox_profile.write_u8(b'"').unwrap();
    for &byte in string.iter() {
        // FIXME(pcwalton): Is this the right way to quote strings in TinyScheme?
        // FIXME(pcwalton): Any other special characters we need to worry about in TinyScheme?
        if byte == b'"' || byte == b'\\' {
            sandbox_profile.write_u8(b'\\').unwrap()
        }
        sandbox_profile.write_u8(byte).unwrap()
    }
    sandbox_profile.write_u8(b'"').unwrap()
}

extern {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
}

