#![feature(globs)]
#![no_std]
#![feature(lang_items)]

extern crate core;
extern crate libc;

use core::ptr;
use core::intrinsics::transmute;
use core::prelude::*;
use libc::{c_char, c_void, c_int, c_uint, size_t};
use pam_modules::{PamConv, PamItemType, PamHandle, PamMessage, PamMsgStyle, PamResponse,
                  PamResult, pam_get_item, syslog, printf};
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

fn get_password(pamh: PamHandle) -> Result<*const c_char, &'static str> {
    get_conv(pamh).ok_or("Failed to get conversation callback.").and_then(|conv| {
        conv.cb.ok_or("Error, callback is null").and_then(|cb| {
            syslog(pamh, "WE GOT A FUCKING CALLBACK !");
            let msgs = [ PamMessage {
                msg_style: PamMsgStyle::PROMPT_ECHO_OFF,
                msg: b"".as_ptr(),
            } ];
            let mut responses: *mut PamResponse = ptr::null_mut();
            // Send 1 message to client, asking for a password.
            // We have to cleanup and free resp array
            if cb(1, &mut (msgs.as_ptr()), &mut responses, conv.appdata_ptr) == 1 {
                Err("Error in conversation callback.")
            } else {
                unsafe { responses.as_ref() }.ok_or("Error, no reponse array.")
                        .and_then(|rsp| Ok(rsp.resp as *const c_char))
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
            printf(b"Got a password : %s\n".as_ptr(), pass);
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
