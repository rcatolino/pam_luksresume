#![feature(libc)]

extern crate libc;

use std::env;
use std::io;
use libc::setuid;
use cryptsetup::CryptDevice;

mod cryptsetup;

fn main() {
    let mut args = env::args();
    let dev_name = match args.nth(1) {
        Some(name) => name,
        None => {
            println!("Error, usage : pam_luksresume_helper <device name>");
            env::set_exit_status(-1);
            return;
        }
    };

    let crypt_dev = if unsafe { setuid(0) == -1 } {
        Err((1, String::from_str("Error, not running as setuid root")))
    } else {
        CryptDevice::new_by_name(dev_name.as_str())
        .ok_or((2, format!("Error, invalid device name : {}", dev_name)))
    };

    let result = crypt_dev.and_then(|cd| {
        CryptDevice::set_debug(true);
        if cd.luks_load() {
            Ok(cd)
        } else {
            Err((3, String::from_str("Device load failed")))
        }
    }).and_then(|cd| {
        let mut inpass = String::new();
        match io::stdin().read_line(&mut inpass) {
            Ok(_) => if cd.resume(inpass.trim_right_matches('\n')) {
                Ok(())
            } else {
                Err((4, String::from_str("Error resuming volume")))
            },
            Err(err) => Err((5, format!("Error reading passphrase: {}", err))),
        }
    }).err();

    match result {
        None => env::set_exit_status(0),
        Some((ret, err)) => {
            println!("{}", err);
            env::set_exit_status(ret)
        }
    }
}

