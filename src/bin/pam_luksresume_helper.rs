
extern crate libc;

use std::ptr;
use std::os;
use std::io;
use libc::{c_char, c_void, c_int, strlen, STDOUT_FILENO, write, setuid};
use cryptsetup::{CryptDevice, crypt_init, crypt_free, crypt_set_log_callback,
                 crypt_load, crypt_set_debug_level, crypt_resume_by_passphrase};
mod cryptsetup;

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn crypt_log_cb(level: c_int, msg: *const c_char, _: *const c_void) {
    unsafe {
        write(STDOUT_FILENO, msg as *const c_void, strlen(msg));
    }
}

fn main() {
    let mut crypt_dev: CryptDevice = ptr::null_mut();
    let args = os::args();
    let dev_path = match args.get(1) {
        Some(path) => path,
        None => {
            println!("Error, usage : pam_luksresume_helper <device_path>");
            os::set_exit_status(-1);
            return;
        }
    };

    let ret = if unsafe { setuid(0) == -1 } {
        println!("Error, not running as setuid root");
        -1i
    } else if unsafe { crypt_init(&mut crypt_dev, dev_path.to_c_str().as_ptr()) != 0 } {
        println!("Error, invalid device {}", dev_path);
        -2i
    } else {
        unsafe {
            crypt_set_log_callback(crypt_dev, crypt_log_cb, ptr::null());
            crypt_set_debug_level(2 as c_int);
        }

        let ret = if unsafe { crypt_load(crypt_dev, b"LUKS1\0".as_ptr() as *const c_char,
                                ptr::null()) != 0 } {
            println!("Device load failed");
            -3i
        } else if unsafe { crypt_resume_by_passphrase(crypt_dev,
                                             b"_dev_sda4\0".as_ptr() as *const c_char,
                                             -1 as c_int,
                                             b"phj15h22pyf".as_ptr() as *const c_char,
                                             b"phj15h22pyf".len() as u64) != 0  } {
            println!("Error resuming volume");
            -4i
        } else {
            0i
        };
        unsafe { crypt_free(crypt_dev) };
        ret
    };

    os::set_exit_status(ret);
}

