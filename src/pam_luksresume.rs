#![feature(globs)]
#![no_std]
#![feature(lang_items)]

extern crate core;
extern crate libc;

use core::ptr;
use core::intrinsics::transmute;
use core::prelude::*;
use libc::{c_char, c_void, c_int, c_uint, size_t};
use pam_modules::{PamConv, PamItemType, PamHandle, PamResult,
                  pam_get_item, syslog, printf};
mod pam_modules;

#[lang = "stack_exhausted"] extern fn stack_exhausted() {}
#[lang = "eh_personality"] extern fn eh_personality() {}
#[lang = "panic_fmt"] fn panic_fmt() -> ! { loop {} }

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_open_session(pamh: PamHandle, flags: c_uint,
                           argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_open_session");
	PamResult::SERVICE_ERR
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_close_session(pamh: PamHandle, flags: c_uint,
                            argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_close_session");
	PamResult::SERVICE_ERR
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_authenticate(pamh: PamHandle, flags: c_uint,
                           argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_authenticate");
    match get_conv(pamh) {
        Some(conv) => {
            syslog(pamh, "got conversation structure !");
            match conv.cb {
                Some(cb) => syslog(pamh, "WE GOT A FUCKING CALLBACK !"),
                None => syslog(pamh, "no callback..."),
            }
        }
        None => return PamResult::AUTHINFO_UNAVAIL,
    }

	PamResult::SUCCESS
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_setcred(pamh: PamHandle, flags: c_uint,
                      argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_setcred");
	PamResult::SERVICE_ERR
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_acct_mgmt(pamh: PamHandle, flags: c_uint,
                        argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_acct_mgmt");
	PamResult::SERVICE_ERR
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_chauthtok(pamh: PamHandle, flags: c_uint,
                        argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_chauthtok");
	PamResult::SERVICE_ERR
}

fn get_conv(pamh: PamHandle) -> Option<PamConv> {
    let mut raw_conv : *const c_void = ptr::null();
    match unsafe {
        pam_get_item(pamh, PamItemType::PAM_CONV as c_int, &mut raw_conv)
    } {
        PamResult::SUCCESS => match unsafe { raw_conv.as_ref() } {
            None => {
                syslog(pamh, "Error getting conversation structure, null result");
                None
            }
            Some(conv) => unsafe {
                Some(*transmute::<*const c_void, *const PamConv>(conv))
            }
        },
        _ => {
            syslog(pamh, "Error geting conversation structure");
            None
        }
    }
}

/*
fn get_password(pamh: PamHandle) -> Option<*const c_char> {
    let password: *const c_char = ptr::null();
    match unsafe {
        pam_get_item(pamh, PamItemType::PAM_AUTHTOK, &mut (password as *const c_void))
    } {
        PamResult::SUCCESS => Some(password),
        _ => {
            syslog(pamh, "Error geting password");
            None
        }
    }
}
*/
