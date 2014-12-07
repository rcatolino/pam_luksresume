#![feature(globs)]
#![no_std]
#![feature(lang_items)]

extern crate libc;
extern crate core;

use libc::{c_uint, size_t};
use pam_modules::{PamHandle, PamResult};
mod pam_modules;

// provided by libstd.
#[lang = "stack_exhausted"] extern fn stack_exhausted() {}
#[lang = "eh_personality"] extern fn eh_personality() {}
#[lang = "panic_fmt"] fn panic_fmt() -> ! { loop {} }

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


