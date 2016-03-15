// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Creation and destruction of sandboxes.

use platform::process::{self, Process};
use profile::Profile;

use std::collections::HashMap;
use std::convert::AsRef;
use std::env;
use std::ffi::{CString, OsStr};
use std::io;

pub use platform::{ChildSandbox, Sandbox};

/// All platform-specific sandboxes implement this trait.
///
/// A new sandbox can be created with `Sandbox::new()`, which all platform-specific sandboxes
/// implement.
pub trait SandboxMethods {
    /// Returns this sandbox profile.
    fn profile(&self) -> &Profile;

    /// Spawns a child process eligible for sandboxing.
    fn start(&self, command: &mut Command) -> io::Result<Process>;
}

/// All platform-specific sandboxes in the child process implement this trait.
pub trait ChildSandboxMethods {
    /// Activates the restrictions in this child process from here on out. Be sure to check the
    /// return value!
    fn activate(&self) -> Result<(),()>;
}

fn cstring<T>(path: T) -> CString
    where T: AsRef<OsStr>
{
    let path = path.as_ref();
    let bytes = if cfg!(windows) {
        path.to_str().unwrap().as_bytes()
    } else {
        use std::os::unix::ffi::OsStrExt;
        path.as_bytes()
    };
    CString::new(bytes).unwrap()
}

pub struct Command {
    /// A path to the executable.
    pub module_path: CString,
    /// The arguments to pass.
    pub args: Vec<CString>,
    /// The environment of the process.
    pub env: HashMap<CString,CString>,
}

impl Command {
    /// Constructs a new `Command` for launching the executable at path `module_path` with no
    /// arguments and no environment by default. Builder methods are provided to change these
    /// defaults and otherwise configure the process.
    pub fn new<T>(module_path: T) -> Command where T: AsRef<OsStr> {
        Command {
            module_path: cstring(module_path),
            args: Vec::new(),
            env: HashMap::new(),
        }
    }

    /// Constructs a new `Command` for launching the current executable.
    pub fn me() -> io::Result<Command> {
        Ok(Command::new(try!(env::current_exe())))
    }

    /// Adds an argument to pass to the program.
    pub fn arg<'a,T>(&'a mut self, arg: T) -> &'a mut Command where T: AsRef<OsStr> {
        self.args.push(cstring(arg));
        self
    }

    /// Adds multiple arguments to pass to the program.
    pub fn args<'a,T>(&'a mut self, args: &[T]) -> &'a mut Command where T: AsRef<OsStr> {
        self.args.extend(args.iter().map(cstring));
        self
    }

    /// Inserts or updates an environment variable mapping.
    pub fn env<'a,T,U>(&'a mut self, key: T, val: U) -> &'a mut Command
                       where T: AsRef<OsStr>, U: AsRef<OsStr> {
        self.env.insert(cstring(key), cstring(val));
        self
    }

    /// Executes the command as a child process, which is returned.
    pub fn spawn(&self) -> io::Result<Process> {
        process::spawn(self)
    }
}

