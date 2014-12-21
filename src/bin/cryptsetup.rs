#![allow(dead_code)]

use libc::{c_char, c_int, c_void, size_t};

pub type CryptDevice = *mut c_int;
#[repr(C)]
pub struct CryptParamsPlain {
    pub hash: *const c_char,
    pub offset: u64,
    pub skip: u64,
    pub size: u64,
}
#[repr(C)]
pub struct CryptParamsLuks1 {
    pub hash: *const c_char,
    pub data_alignment: size_t,
    pub data_device: *const c_char,
}
#[repr(C)]
pub struct CryptActiveDevice {
    pub offset: u64,
    pub iv_offset: u64,
    pub size: u64,
    pub flags: u32,
}

#[repr(C)]
pub enum CryptStatusInfo {
    INVALID = 0,
    INACTIVE = 1,
    ACTIVE = 2,
    BUSY = 3,
}

#[link(name="cryptsetup")]
extern "C" {
    pub fn crypt_init(cd: *mut CryptDevice, device: *const c_char) -> c_int;
    pub fn crypt_init_by_name_and_header(cd: *mut CryptDevice,
                                         name: *const c_char,
                                         header_device: *const c_char) -> c_int;
    pub fn crypt_init_by_name(cd: *mut CryptDevice, name: *const c_char) -> c_int;
    pub fn crypt_set_log_callback(cd: CryptDevice,
                                  log: extern "C" fn (lvl: c_int, msg: *const c_char,
                                                      usrptr: *const c_void),
                                  usrptr: *const c_void);
    pub fn crypt_log(cd: CryptDevice, level: c_int, msg: *const u8);
    pub fn crypt_set_iterarion_time(cd: CryptDevice, iteration_time_ms: u64);
    pub fn crypt_set_data_device(cd: CryptDevice, device: *const c_char) -> c_int;
    pub fn crypt_memory_lock(cd: CryptDevice, lock: c_int) -> c_int;
    pub fn crypt_get_type(cd: CryptDevice) -> *const c_char;
    pub fn crypt_load(cd: CryptDevice, requested_type: *const c_char,
                      params: *const c_void) -> c_int;
    pub fn crypt_suspend(cd: CryptDevice, name: *const c_char) -> c_int;
    pub fn crypt_resume_by_passphrase(cd: CryptDevice,
                                      name: *const c_char,
                                      keyslot: c_int,
                                      passphrase: *const c_char,
                                      passphrase_size: size_t) -> c_int;
    pub fn crypt_free(cd: CryptDevice);
    pub fn crypt_volume_key_verify(cd: CryptDevice,
                                   volume_key: *const c_char,
                                   volume_key_size: size_t) -> c_int;
    pub fn crypt_status(cd: CryptDevice,
                        name: *const c_char) -> CryptStatusInfo;
    pub fn crypt_dump(cd: CryptDevice) -> c_int;
    pub fn crypt_get_uuid(cd: CryptDevice) -> *const c_char;
    pub fn crypt_get_device_name(cd: CryptDevice) -> *const c_char;
    pub fn crypt_get_dir() -> *const c_char;
    pub fn crypt_set_debug_level(level: c_int);
}
