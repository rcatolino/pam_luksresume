extern crate libc;
extern crate pamsm;

use std::error::Error;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::ffi::CStr;
use std::result::Result;
use std::result::Result::{Ok,Err};
use pamsm::{PamServiceModule, Pam};
use pamsm::pam_raw::{PamFlag, PamError};

fn try_resume(pass: &CStr, helper_path: &str,
              dev_name: &str, debug: bool) -> Result<i32, std::io::Error> {
    let mut cmd = Command::new(helper_path);
    let debug = if debug {
        "debug"
    } else {
        ""
    };
    cmd.env_clear().stdin(Stdio::piped()).arg(dev_name).arg(debug).spawn().and_then(|mut process| {
        process.stdin.as_mut().map(|mut pipe| pipe.write(pass.to_bytes()));
        process.wait()
    }).map(|status| status.code().unwrap_or(255))
}

struct SM;

macro_rules! debug {
    ($debug:expr, $( $arg:expr ),*) => {
        if $debug {
            println!($( $arg, )*)
        }
    }
}

impl PamServiceModule for SM {
    fn authenticate(self: &Self, pamh: Pam, _: PamFlag, args: Vec<String>) -> PamError {
        if args.len() < 2 {
            println!("Missing argument, usage : pam_luksresume.so <path to helper> <device name>");
            return PamError::SERVICE_ERR;
        }

        let helper = &args[0];
        let dev_name = &args[1];

        let debug = args.len() == 3 && args[2] == "debug";

        match pamh.get_authtok(None) {
            Ok(None) => {
                debug!(debug, "No credentials available");
                PamError::CRED_UNAVAIL
            }
            Ok(Some(pass)) => {
                match try_resume(pass, helper, dev_name, debug) {
                    Err(e) => {
                        debug!(debug, "{}", e.description());
                        PamError::SERVICE_ERR
                    },
                    Ok(ret_val) if ret_val == 0 => {
                        debug!(debug, "Successful authentication");
                        PamError::SUCCESS
                    },
                    Ok(ret_val) if ret_val == 255 => {
                        debug!(debug, "Bad passphrase");
                        PamError::AUTH_ERR
                    },
                    Ok(ret_val) => {
                        debug!(debug, "Error {} in pam_luksresume_helper", ret_val);
                        PamError::SERVICE_ERR
                    }
                }
            }
            Err(e) => {
                debug!(debug, "Error retrieving authentication token : {}", e);
                PamError::SERVICE_ERR
            }
        }
    }
}


#[no_mangle]
pub extern "C" fn get_pam_sm() -> Box<PamServiceModule> {
    return Box::new(SM {});
}


