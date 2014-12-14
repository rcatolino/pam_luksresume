#![feature(globs)]
#![no_std]
#![feature(lang_items)]

extern crate core;
extern crate libc;

use core::ptr;
use core::intrinsics::transmute;
use core::prelude::*;
use libc::{c_void, c_int, c_uint, size_t};
use pam_modules::{PamConv, PamItemType, PamHandle, PamMessage, PamMsgStyle, PamResponse,
                  PamResponsePtr, PamResult, pam_get_item, syslog, printf};
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

fn get_conv(pamh: PamHandle) -> Result<PamConv, &'static str> {
    let mut raw_conv : *const c_void = ptr::null();
    match unsafe {
        pam_get_item(pamh, PamItemType::PAM_CONV as c_int, &mut raw_conv)
    } {
        PamResult::SUCCESS => unsafe { raw_conv.as_ref() }
            .ok_or("Error getting conversation structure, null result")
            .map(|conv| unsafe { *transmute::<*const c_void, *const PamConv>(conv) }),
        _ => Err("Failed to get conversation item.")
    }
}

fn get_password(pamh: PamHandle) -> Result<PamResponsePtr, &'static str> {
    get_conv(pamh).and_then(|conv| {
        conv.cb.ok_or("Error, callback is null").and_then(|cb| {
            let msgs = [ PamMessage {
                msg_style: PamMsgStyle::PROMPT_ECHO_OFF,
                msg: b"".as_ptr(),
            } ];
            let mut ptr: *mut PamResponse = ptr::null_mut();
            // Send 1 message to client, asking for a password.
            // We have to cleanup and free resp array
            if cb(1, &mut (msgs.as_ptr()), &mut ptr, conv.appdata_ptr) == 1 {
                Err("Error in conversation callback.")
            } else {
                PamResponsePtr::new(ptr).ok_or("Error, unallocated response array")
            }
        })
    })
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_authenticate(pamh: PamHandle, flags: c_uint,
                                      argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_authenticate");
    match get_password(pamh) {
        Ok(pass) => unsafe {
            printf(b"Got a password : %s\n".as_ptr(), pass.get_buff());
            syslog(pamh, "droping password");
            PamResult::SUCCESS
        },
        Err(msg) => {
            syslog(pamh, msg);
            PamResult::AUTHINFO_UNAVAIL
        },
    }
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

