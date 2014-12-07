#![allow(dead_code)]

use core::option::Option;

pub enum PamHandleHidden { }
pub type PamHandle = PamHandleHidden;
#[repr(C)]
#[allow(dead_code)]
pub struct PamMessage {
    pub msg_style: ::libc::c_int,
    pub msg: *const ::libc::c_char,
}
#[repr(C)]
#[allow(dead_code)]
pub struct PamResponse {
    pub resp: *mut ::libc::c_char,
    pub resp_retcode: ::libc::c_int,
}
#[repr(C)]
#[allow(dead_code)]
pub struct PamConv {
    pub conv: Option<extern "C" fn (arg1: ::libc::c_int, arg2: *mut *const PamMessage,
                                    arg3: *mut *mut PamResponse, arg4: *mut ::libc::c_void)
                                    -> ::libc::c_int>,
    pub appdata_ptr: *mut ::libc::c_void,
}
#[repr(C)]
#[allow(dead_code)]
pub enum PamResult {
     PAM_SUCCESS    = 0,		/* Successful function return */
     PAM_OPEN_ERR   = 1,		/* dlopen() failure when dynamically */
     PAM_SYMBOL_ERR     = 2,	/* Symbol not found */
     PAM_SERVICE_ERR    = 3,	/* Error in service module */
     PAM_SYSTEM_ERR     = 4,	/* System error */
     PAM_BUF_ERR    = 5,		/* Memory buffer error */
     PAM_PERM_DENIED    = 6,	/* Permission denied */
     PAM_AUTH_ERR   = 7,		/* Authentication failure */
     PAM_CRED_INSUFFICIENT  = 8,	/* Can not access authentication data */
     PAM_AUTHINFO_UNAVAIL   = 9,	/* Underlying authentication service can not retrieve authentication information  */
     PAM_USER_UNKNOWN   = 10,	/* User not known to the underlying authenticaiton module */
     PAM_MAXTRIES   = 11,		/* An authentication service has maintained a retry count which has been reached. No further retries should be attempted */
     PAM_NEW_AUTHTOK_REQD   = 12,	/* New authentication token required. */
     PAM_ACCT_EXPIRED   = 13,	/* User account has expired */
     PAM_SESSION_ERR    = 14,	/* Can not make/remove an entry for the specified session */
     PAM_CRED_UNAVAIL   = 15,	/* Underlying authentication service can not retrieve user credentials */
     PAM_CRED_EXPIRED   = 16,	/* User credentials expired */
     PAM_CRED_ERR   = 17,		/* Failure setting user credentials */
     PAM_NO_MODULE_DATA     = 18,	/* No module specific data is present */
     PAM_CONV_ERR   = 19,		/* Conversation error */
     PAM_AUTHTOK_ERR    = 20,	/* Authentication token manipulation error */
     PAM_AUTHTOK_RECOVERY_ERR   = 21, /* Authentication information cannot be recovered */
     PAM_AUTHTOK_LOCK_BUSY  = 22,   /* Authentication token lock busy */
     PAM_AUTHTOK_DISABLE_AGING  = 23, /* Authentication token aging disabled */
     PAM_TRY_AGAIN  = 24,	/* Preliminary check by password service */
     PAM_IGNORE     = 25,		/* Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient */
     PAM_ABORT  = 26,            /* Critical error (?module fail now request) */
     PAM_AUTHTOK_EXPIRED    = 27, /* user's authentication token has expired */
     PAM_MODULE_UNKNOWN     = 28, /* module is not known */
     PAM_BAD_ITEM           = 29, /* Bad item passed to pam_*_item() */
     PAM_CONV_AGAIN         = 30, /* conversation function is event driven and data is not available yet */
     PAM_INCOMPLETE         = 31, /* please call this function again to complete authentication stack. Before calling again, verify that conversation is completed */
}

/* Note: these flags are used for pam_setcred() */
/* Set user credentials for an authentication service */
pub mod pam_flags {
    static PAM_ESTABLISH_CRED : ::libc::c_uint = 0x0002;
    static PAM_DELETE_CRED : ::libc::c_uint = 0x0004;
    static PAM_REINITIALIZE_CRED : ::libc::c_uint = 0x0008;
    static PAM_REFRESH_CRED : ::libc::c_uint = 0x0010;
    static PAM_CHANGE_EXPIRED_AUTHTOK : ::libc::c_uint = 0x0020;
}

#[repr(C)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct PamXauthData {
    pub namelen: ::libc::c_int,
    pub name: *mut ::libc::c_char,
    pub datalen: ::libc::c_int,
    pub data: *mut ::libc::c_char,
}
extern "C" {
    pub fn set_item(pamh: *mut PamHandle, item_type: PamItemType,
                        item: *const ::libc::c_void) -> PamResult;
    pub fn get_item(pamh: *const PamHandle, item_type: PamItemType,
                        item: *mut *const ::libc::c_void) -> PamResult;
    pub fn strerror(pamh: *mut PamHandle, errnum: ::libc::c_int)
     -> *const ::libc::c_char;
    pub fn putenv(pamh: *mut PamHandle,
                      name_value: *const ::libc::c_char) -> PamResult;
    pub fn getenv(pamh: *mut PamHandle, name: *const ::libc::c_char)
     -> *const ::libc::c_char;
    pub fn getenvlist(pamh: *mut PamHandle)
     -> *mut *mut ::libc::c_char;
    pub fn fail_delay(pamh: *mut PamHandle,
                          musec_delay: ::libc::c_uint) -> PamResult;
    pub fn set_data(pamh: *mut PamHandle,
                        module_data_name: *const ::libc::c_char,
                        data: *mut ::libc::c_void,
                        cleanup: Option<extern "C" fn (arg1: *mut PamHandle,
                                                       arg2: *mut ::libc::c_void,
                                                       arg3: ::libc::c_int)>)
     -> PamResult;
    pub fn get_data(pamh: *const PamHandle,
                        module_data_name: *const ::libc::c_char,
                        data: *mut *const ::libc::c_void) -> PamResult;
    pub fn get_user(pamh: *mut PamHandle,
                        user: *mut *const ::libc::c_char,
                        prompt: *const ::libc::c_char) -> PamResult;
    pub fn sm_authenticate(pamh: *mut PamHandle, flags: u32,
                               argc: ::libc::c_int,
                               argv: *mut *const ::libc::c_char)
     -> PamResult;
    pub fn sm_setcred(pamh: *mut PamHandle, flags: ::libc::c_uint,
                          argc: ::libc::c_int,
                          argv: *mut *const ::libc::c_char) -> PamResult;
    pub fn sm_acct_mgmt(pamh: *mut PamHandle, flags: ::libc::c_uint,
                            argc: ::libc::c_int,
                            argv: *mut *const ::libc::c_char)
     -> PamResult;
    pub fn sm_open_session(pamh: *mut PamHandle, flags: ::libc::c_uint,
                               argc: ::libc::c_int,
                               argv: *mut *const ::libc::c_char)
     -> PamResult;
    pub fn sm_close_session(pamh: *mut PamHandle, flags: ::libc::c_uint,
                                argc: ::libc::c_int,
                                argv: *mut *const ::libc::c_char)
     -> PamResult;
    pub fn sm_chauthtok(pamh: *mut PamHandle, flags: ::libc::c_uint,
                            argc: ::libc::c_int,
                            argv: *mut *const ::libc::c_char)
     -> PamResult;
}


