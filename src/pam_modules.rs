#![allow(dead_code)]

use std::intrinsics::volatile_set_memory;
use std::prelude::*;
use libc::{c_char, c_int, c_uint, c_void, free, strlen};

pub type PamHandle = *const c_uint;
#[repr(C)]
pub enum PamMsgStyle {
    PROMPT_ECHO_OFF =1,	/* Ask for password without echo */
    PROMPT_ECHO_ON  =2,	/* Ask for password with echo */
    ERROR_MSG       =3,	/* Display an error message */
    TEXT_INFO       =4,	/* Display arbitrary text */
}
#[repr(C)]
pub enum PamResult {
     SUCCESS    = 0,		/* Successful function return */
     OPEN_ERR   = 1,		/* dlopen() failure when dynamically */
     SYMBOL_ERR     = 2,	/* Symbol not found */
     SERVICE_ERR    = 3,	/* Error in service module */
     SYSTEM_ERR     = 4,	/* System error */
     BUF_ERR    = 5,		/* Memory buffer error */
     PERM_DENIED    = 6,	/* Permission denied */
     AUTH_ERR   = 7,		/* Authentication failure */
     CRED_INSUFFICIENT  = 8,	/* Can not access authentication data */
     AUTHINFO_UNAVAIL   = 9,	/* Underlying authentication service can not retrieve authentication information  */
     USER_UNKNOWN   = 10,	/* User not known to the underlying authenticaiton module */
     MAXTRIES   = 11,		/* An authentication service has maintained a retry count which has been reached. No further retries should be attempted */
     NEW_AUTHTOK_REQD   = 12,	/* New authentication token required. */
     ACCT_EXPIRED   = 13,	/* User account has expired */
     SESSION_ERR    = 14,	/* Can not make/remove an entry for the specified session */
     CRED_UNAVAIL   = 15,	/* Underlying authentication service can not retrieve user credentials */
     CRED_EXPIRED   = 16,	/* User credentials expired */
     CRED_ERR   = 17,		/* Failure setting user credentials */
     NO_MODULE_DATA     = 18,	/* No module specific data is present */
     CONV_ERR   = 19,		/* Conversation error */
     AUTHTOK_ERR    = 20,	/* Authentication token manipulation error */
     AUTHTOK_RECOVERY_ERR   = 21, /* Authentication information cannot be recovered */
     AUTHTOK_LOCK_BUSY  = 22,   /* Authentication token lock busy */
     AUTHTOK_DISABLE_AGING  = 23, /* Authentication token aging disabled */
     TRY_AGAIN  = 24,	/* Preliminary check by password service */
     IGNORE     = 25,		/* Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient */
     ABORT  = 26,            /* Critical error (?module fail now request) */
     AUTHTOK_EXPIRED    = 27, /* user's authentication token has expired */
     MODULE_UNKNOWN     = 28, /* module is not known */
     BAD_ITEM           = 29, /* Bad item passed to *_item() */
     CONV_AGAIN         = 30, /* conversation function is event driven and data is not available yet */
     INCOMPLETE         = 31, /* please call this function again to complete authentication stack. Before calling again, verify that conversation is completed */
}
#[repr(C)]
pub struct PamMessage {
    pub msg_style: PamMsgStyle,
    pub msg: *const u8,
}

#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: PamResult,
}

impl PamResponse {
    pub fn get_buff(&self) -> *const c_char {
        self.resp as *const c_char
    }

    pub fn cleanup(&mut self) {
        unsafe {
            if ! self.resp.is_null() {
                volatile_set_memory(self.resp, 0u8, strlen(self.resp as *const c_char) as uint);
                free(self.resp as *mut c_void);
            }
            let asptr: *mut PamResponse = self;
            free(asptr as *mut c_void);
        }
    }
}


#[repr(C)]
pub struct PamConv {
    pub cb: Option<extern "C" fn (arg1: c_int, arg2: *mut *const PamMessage,
                                  arg3: *mut *mut PamResponse, arg4: *mut c_void)
                                  -> c_int>,
    pub appdata_ptr: *mut c_void,
}
#[repr(C)]
pub enum LogLvl {
    LOG_EMERG	=0,	/* system is unusable */
    LOG_ALERT	=1,	/* action must be taken immediately */
    LOG_CRIT	=2,	/* critical conditions */
    LOG_ERR		=3,	/* error conditions */
    LOG_WARNING	=4,	/* warning conditions */
    LOG_NOTICE	=5,	/* normal but significant condition */
    LOG_INFO	=6,	/* informational */
    LOG_DEBUG	=7,	/* debug-level messages */
}
/* Note: these flags are used for pam_setcred() */
/* Set user credentials for an authentication service */
pub mod pam_flags {
    use libc::c_uint;
    static PAM_ESTABLISH_CRED : c_uint = 0x0002;
    static PAM_DELETE_CRED : c_uint = 0x0004;
    static PAM_REINITIALIZE_CRED : c_uint = 0x0008;
    static PAM_REFRESH_CRED : c_uint = 0x0010;
    static PAM_CHANGE_EXPIRED_AUTHTOK : c_uint = 0x0020;
}

#[repr(C)]
pub enum PamItemType {
     PAM_SERVICE	    = 1,	/* The service name */
     PAM_USER               = 2,	/* The user name */
     PAM_TTY                = 3,	/* The tty name */
     PAM_RHOST              = 4,	/* The remote host name */
     PAM_CONV               = 5,	/* The pam_conv structure */
     PAM_AUTHTOK            = 6,	/* The authentication token (password) */
     PAM_OLDAUTHTOK         = 7,	/* The old authentication token */
     PAM_RUSER              = 8,	/* The remote user name */
     PAM_USER_PROMPT        = 9,    /* the prompt for getting a username */
     PAM_FAIL_DELAY         = 10,   /* app supplied function to override failure delays */
     PAM_XDISPLAY           = 11,   /* X display name */
     PAM_XAUTHDATA          = 12,   /* X server authentication data */
     PAM_AUTHTOK_TYPE       = 13,   /* The type for pam_get_authtok */
}

#[repr(C)]
pub struct PamXauthData {
    pub namelen: c_int,
    pub name: *mut c_char,
    pub datalen: c_int,
    pub data: *mut c_char,
}
#[link(name="pam")]
extern "C" {
    pub fn pam_set_item(pamh: PamHandle, item_type: PamItemType,
                        item: *const c_void) -> PamResult;
    pub fn pam_get_item(pamh: PamHandle, item_type: c_int,
                        item: *mut *const c_void) -> PamResult;
    pub fn strerror(pamh: PamHandle, errnum: c_int)
     -> *const c_char;
    pub fn putenv(pamh: PamHandle,
                      name_value: *const c_char) -> PamResult;
    pub fn getenv(pamh: PamHandle, name: *const c_char)
     -> *const c_char;
    pub fn getenvlist(pamh: PamHandle)
     -> *mut *mut c_char;
    pub fn fail_delay(pamh: PamHandle,
                          musec_delay: c_uint) -> PamResult;
    pub fn set_data(pamh: PamHandle,
                        module_data_name: *const c_char,
                        data: *mut c_void,
                        cleanup: Option<extern "C" fn (arg1: PamHandle,
                                                       arg2: *mut c_void,
                                                       arg3: c_int)>) -> PamResult;
    pub fn get_data(pamh: PamHandle,
                        module_data_name: *const c_char,
                        data: *mut *const c_void) -> PamResult;
    pub fn get_user(pamh: PamHandle,
                        user: *mut *const c_char,
                        prompt: *const c_char) -> PamResult;
    pub fn sm_authenticate(pamh: PamHandle, flags: u32,
                               argc: c_int,
                               argv: *mut *const c_char) -> PamResult;
    pub fn sm_setcred(pamh: PamHandle, flags: c_uint,
                          argc: c_int,
                          argv: *mut *const c_char) -> PamResult;
    pub fn sm_acct_mgmt(pamh: PamHandle, flags: c_uint,
                            argc: c_int,
                            argv: *mut *const c_char) -> PamResult;
    pub fn sm_open_session(pamh: PamHandle, flags: c_uint,
                               argc: c_int,
                               argv: *mut *const c_char) -> PamResult;
    pub fn sm_close_session(pamh: PamHandle, flags: c_uint,
                                argc: c_int,
                                argv: *mut *const c_char) -> PamResult;
    pub fn sm_chauthtok(pamh: PamHandle, flags: c_uint,
                            argc: c_int,
                            argv: *mut *const c_char) -> PamResult;
    pub fn pam_syslog(pamh: PamHandle, priority: LogLvl, fmt: *const u8);
    pub fn snprintf(buff: *mut c_char, buff_size: ::libc::size_t,
                    fmt: *const u8, string: *const u8) -> c_int;
}

pub fn syslog(pamh: PamHandle, message: &str) {
    let mut buff = [0u8, ..100];
    unsafe {
        if snprintf(buff.as_mut_ptr() as *mut c_char, 100, b"%s\0".as_ptr(),
                    message.as_bytes().as_ptr()) > 0 {
            pam_syslog(pamh, LogLvl::LOG_INFO, buff.as_ptr());
        }
        // XXX: should/could we do something in case of snprintf failure ?
        // panicking seems a little extreme...
    }
}

