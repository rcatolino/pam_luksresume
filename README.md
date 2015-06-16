pam_luksresume
=========
inspired by https://github.com/dorinp/pam-mount

A Linux PAM module that authenticates by resuming a suspended luks container.
It uses the result of the luksResume action to validate the password, instead of
the user account info.

This is useful to resume a luks volume when unlocking a lock screen.

### Build & Install

```
cargo build
```

- Install the shared library in /usr/lib/security/pam_luksresume.so,
or wherever your pam modules are.
- Install the pam_luksresume_helper binary as setuid root in the same directory
(or another one, it doesn't really matter).

### Usage
Make sure to run the luksSuspend action when starting the lockscreen.
Replace the pam method used by your lockscreen (in the /etc/pam.d/$lockscreen file) with :

```
auth require pam_luksresume.so <path to resume helper> <device name>
```

The device name corresponds to the name given to the mapped volume, not
the path to the real device.
