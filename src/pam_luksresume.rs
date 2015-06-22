#![feature(core,lang_items,libc,no_std)]
#![no_std]

extern crate libc;
extern crate std;

use std::error::Error;
use std::io::Write;
use std::mem::transmute_copy;
use std::process::Command;
use std::process::Stdio;
use std::ptr;
use std::result::Result;
use std::result::Result::{Ok,Err};
use std::slice::from_raw_parts;
use std::str::from_utf8;
use libc::{c_char, c_void, c_int, c_uint, size_t, strlen};
use pam_modules::{PamConv, PamItemType, PamHandle, PamMessage, PamMsgStyle, PamResponse,
                  PamResult, pam_get_item, syslog};

mod pam_modules;

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
            .map(|conv| unsafe { transmute_copy::<c_void, PamConv>(conv) }),
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

fn try_resume(pass: &PamResponse, helper_path: &str,
              dev_name: &str) -> Result<i32, std::io::Error> {
    let mut cmd = Command::new(helper_path);
    cmd.env_clear().stdin(Stdio::piped()).arg(dev_name).spawn().and_then(|mut process| {
        process.stdin.as_mut().map(|mut pipe| {
            let ref_ptr = pass.get_buff() as *const u8;
            unsafe {
                pipe.write(from_raw_parts(ref_ptr, strlen(pass.get_buff()) as usize))
            }
        });
        process.wait()
    }).map(|status| status.code().unwrap_or(255))
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn pam_sm_authenticate(pamh: PamHandle, flags: c_uint,
                                      argc: size_t, argv: *const *const u8) -> PamResult {
    syslog(pamh, "In pam_sm_authenticate");
    if argc < 2 {
        syslog(pamh,
               "Missing argument, usage : pam_luksresume.so <path to helper> <device name>");
        return PamResult::SERVICE_ERR;
    }

    let (helper, dev_name) = unsafe {
        let args = from_raw_parts(argv, argc as usize);
        let mbh = from_utf8(from_raw_parts(args[0], strlen(args[0] as *const c_char) as usize));
        let mbn = from_utf8(from_raw_parts(args[1], strlen(args[1] as *const c_char) as usize));
        match (mbh, mbn) {
            (Ok(h), Ok(n)) => (h, n),
            _ => {
                syslog(pamh, "Error, arguments must be utf8 encoded");
                return PamResult::SERVICE_ERR;
            },
        }
    };

    match get_password(pamh) {
        Ok(pass) => {
            let ret = match try_resume(pass, helper, dev_name) {
                Err(e) => {
                    syslog(pamh, e.description());
                    PamResult::SERVICE_ERR
                },
                Ok(ret_val) if ret_val == 0 => {
                    syslog(pamh, "Successful authentication");
                    PamResult::SUCCESS
                },
                Ok(ret_val) if ret_val == -22 => {
                    syslog(pamh, "Bad passphrase");
                    PamResult::AUTH_ERR
                },
                Ok(_) => {
                    syslog(pamh, "Error in pam_luksresume_helper");
                    PamResult::SERVICE_ERR
                }
            };
            pass.cleanup();
            ret
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

