
extern crate libc;

use std::ptr;
use std::os;
use std::io;
use libc::{c_char, c_void, c_int, strlen, STDOUT_FILENO, write, setuid};
use cryptsetup::{CryptDevice, crypt_init_by_name, crypt_free, crypt_set_log_callback,
                 crypt_load, crypt_set_debug_level,
                 crypt_resume_by_passphrase};
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
    let dev_name = match args.get(1) {
        Some(name) => name.to_c_str(),
        None => {
            println!("Error, usage : pam_luksresume_helper <device name>");
            os::set_exit_status(-1);
            return;
        }
    };

    let ret = if unsafe { setuid(0) == -1 } {
        println!("Error, not running as setuid root");
        -1i
    } else if unsafe { crypt_init_by_name(&mut crypt_dev, dev_name.as_ptr()) != 0 } {
        println!("Error, invalid device {}", dev_name);
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
        } else {
            match io::stdin().read_line() {
                Ok(inpass) => {
                    let pass = inpass.trim_right_chars('\n');
                    println!("Using password {}", pass);
                    if unsafe { crypt_resume_by_passphrase(crypt_dev,
                                                 dev_name.as_ptr(),
                                                 -1 as c_int,
                                                 pass.as_ptr() as *const c_char,
                                                 pass.len() as u64) < 0  } {
                        println!("Error resuming volume");
                        -4i
                    } else {
                        0i
                    }
                }
                Err(err) => {
                    println!("Error reading passphrase: {}", err);
                    -5i
                }
            }
        };
        unsafe { crypt_free(crypt_dev) };
        ret
    };

    os::set_exit_status(ret);
}

