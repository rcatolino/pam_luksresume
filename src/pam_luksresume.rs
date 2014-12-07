extern crate libc;

use libc::{c_uint, size_t};
use pam_modules::{PamHandle, PamResult};
mod pam_modules;

/*PAM_EXTERN int pam_sm_open_session(PamHandle *pamh, int flags, argc, argv);
*/
#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_open_session(pamh: PamHandle, flags: c_uint, argc: size_t, argv: *const u8) -> PamResult {
	PamResult::PAM_SERVICE_ERR
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_close_session(pamh: PamHandle, flags: c_uint, argc: size_t, argv: *const u8) -> PamResult {
	PamResult::PAM_SERVICE_ERR
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_authenticate(pamh: PamHandle, flags: c_uint, argc: size_t, argv: *const u8) -> PamResult {
	PamResult::PAM_SUCCESS
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_setcred(pamh: PamHandle, flags: c_uint, argc: size_t, argv: *const u8) -> PamResult {
	PamResult::PAM_SUCCESS
}


