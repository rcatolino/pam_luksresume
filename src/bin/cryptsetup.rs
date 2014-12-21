#![allow(dead_code)]

use libc::{STDOUT_FILENO, c_char, c_int, c_void, size_t, strlen, write};
use std::c_str::CString;
use std::ptr;

pub type InnerCryptDevice = *mut c_int;
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
    pub fn crypt_init(cd: *mut InnerCryptDevice, device: *const c_char) -> c_int;
    pub fn crypt_init_by_name_and_header(cd: *mut InnerCryptDevice,
                                         name: *const c_char,
                                         header_device: *const c_char) -> c_int;
    pub fn crypt_init_by_name(cd: *mut InnerCryptDevice, name: *const c_char) -> c_int;
    pub fn crypt_set_log_callback(cd: InnerCryptDevice,
                                  log: extern "C" fn (lvl: c_int, msg: *const c_char,
                                                      usrptr: *const c_void),
                                  usrptr: *const c_void);
    pub fn crypt_log(cd: InnerCryptDevice, level: c_int, msg: *const u8);
    pub fn crypt_set_iterarion_time(cd: InnerCryptDevice, iteration_time_ms: u64);
    pub fn crypt_set_data_device(cd: InnerCryptDevice, device: *const c_char) -> c_int;
    pub fn crypt_memory_lock(cd: InnerCryptDevice, lock: c_int) -> c_int;
    pub fn crypt_get_type(cd: InnerCryptDevice) -> *const c_char;
    pub fn crypt_load(cd: InnerCryptDevice, requested_type: *const c_char,
                      params: *const c_void) -> c_int;
    pub fn crypt_suspend(cd: InnerCryptDevice, name: *const c_char) -> c_int;
    pub fn crypt_resume_by_passphrase(cd: InnerCryptDevice,
                                      name: *const c_char,
                                      keyslot: c_int,
                                      passphrase: *const c_char,
                                      passphrase_size: size_t) -> c_int;
    pub fn crypt_free(cd: InnerCryptDevice);
    pub fn crypt_volume_key_verify(cd: InnerCryptDevice,
                                   volume_key: *const c_char,
                                   volume_key_size: size_t) -> c_int;
    pub fn crypt_status(cd: InnerCryptDevice,
                        name: *const c_char) -> CryptStatusInfo;
    pub fn crypt_dump(cd: InnerCryptDevice) -> c_int;
    pub fn crypt_get_uuid(cd: InnerCryptDevice) -> *const c_char;
    pub fn crypt_get_device_name(cd: InnerCryptDevice) -> *const c_char;
    pub fn crypt_get_dir() -> *const c_char;
    pub fn crypt_set_debug_level(level: c_int);
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn crypt_log_cb(level: c_int, msg: *const c_char, _: *const c_void) {
    unsafe {
        write(STDOUT_FILENO, msg as *const c_void, strlen(msg));
    }
}

pub struct CryptDevice {
    name: CString,
    indev: InnerCryptDevice,
}

impl CryptDevice {
    pub fn new_by_name(dev_name: &str) -> Option<CryptDevice> {
        let mut crypt_dev: InnerCryptDevice = ptr::null_mut();
        let name = dev_name.to_c_str();
        if unsafe { crypt_init_by_name(&mut crypt_dev, name.as_ptr()) != 0 } {
            None
        } else {
            unsafe {
                crypt_set_log_callback(crypt_dev, crypt_log_cb, ptr::null());
            }
            Some(CryptDevice {
                name: name,
                indev: crypt_dev,
            })
        }
    }

    pub fn set_debug(enabled: bool) {
        unsafe {
            if enabled {
                crypt_set_debug_level(2 as c_int);
            } else {
                crypt_set_debug_level(0 as c_int);
            }
        }
    }

    pub fn luks_load(&self) -> bool {
        unsafe {
            crypt_load(self.indev, b"LUKS1\0".as_ptr() as *const c_char,
                       ptr::null()) == 0
        }
    }

    pub fn resume(&self, pass: &str) -> bool {
        unsafe {
            crypt_resume_by_passphrase(self.indev, self.name.as_ptr(),
                                       -1 as c_int, pass.as_ptr() as *const c_char,
                                       pass.len() as u64) >= 0

        }
    }

    pub fn free(self) {
        println!("Freeing crypt device");
        unsafe { crypt_free(self.indev) };
    }
}
