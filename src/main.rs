#![crate_name = "pam_mount"]
#![crate_type = "dylib"]
extern crate libc;

use libc::{c_int, size_t};
use pam::{pam_handle_t, PamResult};
mod pam;

/*PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, argc, argv);
*/
#[no_mangle]
#[allow(unused_variable)]
pub fn pam_sm_open_session(pamh: pam_handle_t, flags: c_int, argc: size_t, argv: *const u8) -> c_int {
	PAM_SUCCESS as c_int
}

#[no_mangle]
#[allow(unused_variable)]
pub fn pam_sm_close_session(pamh: pam_handle_t, flags: c_int, argc: size_t, argv: *const u8) -> c_int {
	on_session_closed(pam::get_user(pamh).unwrap().as_slice());
	PAM_SUCCESS as c_int
}

// PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
#[no_mangle]
#[allow(unused_variable)]
pub fn pam_sm_authenticate(pamh: pam_handle_t, flags: c_int, argc: size_t, argv: *const u8) -> c_int {
	PAM_SUCCESS as c_int
}

// PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);
#[no_mangle]
#[allow(unused_variable)]
pub fn pam_sm_setcred(pamh: pam_handle_t, flags: c_int, argc: size_t, argv: *const u8) -> c_int {
	// println!("pam_sm_setcred: hello from rust!!! {}", argc);
	PAM_SUCCESS as c_int
}


