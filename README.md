pam-luksresume
=========
inspired by https://github.com/dorinp/pam-mount

A Linux PAM module that authenticate by resuming a suspend luks container.
Uses the result of the luksResume action to validate password. Does not use user unix password.

This is useful to resume a luks volume when unlocking a lock screen.

### Usage
Run the luksSuspend action while starting the lockscreen.
Replace the pam method used by your lockscreen (in the /etc/pam.d/$lockscreen file) with :

```
auth require pam_luksresume.so
```
