
extern crate libc;

use std::os;
use std::io;
use libc::setuid;
use cryptsetup::CryptDevice;
mod cryptsetup;

fn main() {
    let args = os::args();
    let dev_name = match args.get(1) {
        Some(name) => name,
        None => {
            println!("Error, usage : pam_luksresume_helper <device name>");
            os::set_exit_status(-1);
            return;
        }
    };

    let crypt_dev = if unsafe { setuid(0) == -1 } {
        Err((1i, String::from_str("Error, not running as setuid root")))
    } else {
        CryptDevice::new_by_name(dev_name.as_slice())
        .ok_or((2i, format!("Error, invalid device name : {}", dev_name)))
    };

    let result = crypt_dev.and_then(|cd| {
        CryptDevice::set_debug(true);
        if cd.luks_load() {
            Ok(cd)
        } else {
            Err((3i, String::from_str("Device load failed")))
        }
    }).and_then(|cd| {
        match io::stdin().read_line() {
            Ok(inpass) => if cd.resume(inpass.trim_right_chars('\n')) {
                Ok(())
            } else {
                Err((4i, String::from_str("Error resuming volume")))
            },
            Err(err) => Err((5i, format!("Error reading passphrase: {}", err))),
        }
    }).err();

    match result {
        None => os::set_exit_status(0),
        Some((ret, err)) => {
            println!("{}", err);
            os::set_exit_status(ret)
        }
    }
}

