#![feature(globs)]
#![no_std]
#![feature(lang_items)]

extern crate core;
extern crate libc;

use core::ptr;
use core::ptr::RawMutPtr;
use core::intrinsics::transmute;
use core::prelude::*;
use libc::{c_char, c_void, c_int, c_uint, size_t};
use libc::funcs::posix88::unistd::{getegid, setgid};
use pam_modules::{PamConv, PamItemType, PamHandle, PamMessage, PamMsgStyle, PamResponse,
                  PamResult, LogLvl, pam_get_item, syslog, pam_syslog, snprintf, printf};
use cryptsetup::{CryptDevice, crypt_init, crypt_init_by_name, crypt_free,
                 crypt_log, crypt_set_log_callback};

mod cryptsetup;
mod pam_modules;

#[lang = "stack_exhausted"] extern fn stack_exhausted() {}
#[lang = "eh_personality"] extern fn eh_personality() {}
#[lang = "panic_fmt"] fn panic_fmt() -> ! { loop {} }

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn crypt_log_cb(level: c_int, msg: *const u8, pamh: *const c_void) {
    unsafe {
        let mut buff = [0u8, ..100];
        if snprintf(buff.as_mut_ptr() as *mut c_char, 100, b"%s".as_ptr(), msg) > 0 {
            pam_syslog(pamh as PamHandle, LogLvl::LOG_INFO, buff.as_ptr());
        }
    }
}

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

fn get_password<'a>(pamh: PamHandle) -> Result<&'a mut PamResponse, &'static str> {
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
                unsafe { ptr.as_mut() }.ok_or("Error, unallocated response array")
            }
        })
    })
}

fn try_resume<'a>(pamh: PamHandle, pass: &'a PamResponse) {
    let mut crypt_dev: CryptDevice = ptr::null_mut();
    unsafe {
        // Need privileges ?
        setgid(6);
        printf(b"Current egid : %d\n\0".as_ptr(), getegid() as *const c_char);
        let errno = crypt_init(&mut crypt_dev, b"/dev/dm-1".as_ptr() as *const c_char);
        if errno != 0 {
            printf(b"Failed to initialize dm-crypt backend : %d\n\0".as_ptr(), errno as *const c_char);
        } else {
            crypt_set_log_callback(crypt_dev, crypt_log_cb, pamh as *const c_void);
            crypt_free(crypt_dev);
        }
    }
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_authenticate(pamh: PamHandle, flags: c_uint,
                                      argc: size_t, argv: *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_authenticate");
    match get_password(pamh) {
        Ok(pass) => unsafe {
            printf(b"Got a password : %s\n".as_ptr(), pass.get_buff());
            try_resume(pamh, pass);
            pass.cleanup();
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

