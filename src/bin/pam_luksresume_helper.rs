
extern crate libc;

use std::env;
use std::process::exit;
use std::io;
use libc::setuid;
use cryptsetup::CryptDevice;

mod cryptsetup;

fn main() {
    exit(real_main());
}

fn real_main() -> i32 {
    let mut args = env::args();
    let dev_name = match args.nth(1) {
        Some(name) => name,
        None => {
            println!("Error, usage : pam_luksresume_helper <device name>");
            return -1;
        }
    };

    let crypt_dev = if unsafe { setuid(0) == -1 } {
        Err((1, String::from("Error, not running as setuid root")))
    } else {
        CryptDevice::new_by_name(dev_name.as_str())
        .ok_or((2, format!("Error, invalid device name : {}", dev_name)))
    };

    let result = crypt_dev.and_then(|cd| {
        CryptDevice::set_debug(true);
        if cd.luks_load() {
            Ok(cd)
        } else {
            Err((3, String::from("Device load failed")))
        }
    }).and_then(|cd| {
        let mut inpass = String::new();
        match io::stdin().read_line(&mut inpass) {
            Ok(_) => {
                match cd.resume(inpass.trim_right_matches('\n')) {
                    errno if errno < 0 => {
                        if errno as u8 == 0 { errno == -1; }
                        Err((errno as i32, format!("Error resuming volume, errno : {}", errno)))
                    }
                    _ => Ok(()),
                }
            },
            Err(err) => Err((5, format!("Error reading passphrase: {}", err))),
        }
    }).err();

    match result {
        None => 0,
        Some((ret, err)) => {
            println!("{}", err);
            ret
        }
    }
}

