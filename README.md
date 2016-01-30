# gaol

## Introduction

`gaol` is a cross-platform, operating-system-level *application sandboxing* library written in Rust. It allows you to restrict the set of operations that your application is allowed to perform, to provide a layer of defense against malicious or accidental attempts to perform unexpected operations.

See `examples/example.rs` and the tests for examples of usage.

*At the moment, `gaol` is only lightly reviewed for correctness and security.* It should not be considered mature or "battle-tested". Use at your own risk.

[Documentation](https://doc.servo.org/gaol/index.html)

## Operation

`gaol` is designed to be used in a multiprocess scenario. (This is necessary for sandboxing on some operating systems, for example Windows and Linux.) In the parent process, you create a *profile*—a set of operations that the process is allowed to perform—and then spawn less-privileged processes subject to the restrictions in the profile. A profile is a *whitelist* of operations rather than a blacklist; operations not in the profile are automatically prohibited. See the documentation in the `profile` module for an exhaustive list of allowed and prohibited operations.

Not all operating systems support whitelisting all operations that `gaol` supports. If the profile contains operations that the current operating system cannot allow on a precise basis, then the profile constructor will return an error. This minimizes the chance that operations are accidentally allowed. You can query each operation to determine how well it is supported on the current OS with the `support()` method.

## Broker processes

Many applications that employ sandboxing use a privileged *broker process* to enable privileged operations that the sandbox profile can't precisely describe. For example, if the current operating system doesn't natively allow TCP connections to be restricted based on port (a restriction that Linux has), an effective workaround is to deny all network connections in the untrusted process, have the untrusted process send an IPC message to a broker whenever it wants to perform a network connection, and have the broker verify that the port is allowed before performing the operation on behalf of the untrusted process. Another useful use of a broker process is to require user consent before performing potentially dangerous operations; for example, one may want to require that the user navigate to a file via a dialog box before granting the untrusted process permission to access that file.

Although `gaol` is designed to be used in a multiprocess scenario, it does not natively provide any "broker" functionality. This is because the broker functionality is often application- or OS-specific: for example, there is no cross-platform way to display dialog boxes. Broker processes are therefore out of scope for `gaol` itself. However, it may well be useful for certain applications to layer a generic broker process *on top* of `gaol`. This functionality would be best left to a separate crate that would work in tandem with `gaol` to provide flexible sandboxing.

