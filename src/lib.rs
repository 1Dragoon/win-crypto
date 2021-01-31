mod bindings {
    ::windows::include_bindings!();
}

use std::ptr;

use bindings::{
    windows::win32::security::CryptUnprotectData,
    windows::win32::security::CryptProtectData,
    windows::win32::security::CRYPTOAPI_BLOB,
    windows::win32::system_services::LocalFree,
};

use std::fmt;
use std::error::Error;

#[derive(Debug, Clone)]
pub struct WinEncryptError;

#[derive(Debug, Clone)]
pub struct WinDecryptError;

impl Error for WinEncryptError {}
impl Error for WinDecryptError {}

impl fmt::Display for WinEncryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Windows encryption error")
    }
}

impl fmt::Display for WinDecryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Windows decryption error")
    }
}

pub fn decrypt(encrypted: &str) -> Result<String, Box<dyn Error>> {
    let mut et_bytes = hex::decode(encrypted)?;

    let p_data_in = &mut CRYPTOAPI_BLOB {
        cb_data: et_bytes.len() as _,
        pb_data: et_bytes.as_mut_ptr(),
    };
    let p_data_out = &mut CRYPTOAPI_BLOB::default();
   
    let result;
    unsafe {
        result = CryptUnprotectData(
            p_data_in,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            p_data_out
        );
    }

    if result.0 == 1 {
    
        let output;
        unsafe {
            // cb_data represents length in terms of u8, so divide by 2 to represent length in UTF-16 units
            output = widestring::U16String::from_ptr(p_data_out.pb_data as _, (p_data_out.cb_data/2) as _).to_string_lossy();
            LocalFree(p_data_out.pb_data as _);
        }
        Ok(output)
    } else {
        Err(Box::new(WinDecryptError))
    }
}

pub fn encrypt(input: &str) -> Result<String, WinEncryptError> {
    let mut input_utf16: Vec<u16> = input.encode_utf16().collect();
    // input_utf16.push(0);

    let p_data_in = &mut CRYPTOAPI_BLOB {
        // number of bytes; hence twice the number of elements
        cb_data: (input_utf16.len()*2) as _,
        pb_data: input_utf16.as_mut_ptr() as _,
    };
    let p_data_out = &mut CRYPTOAPI_BLOB::default();
   
    let result;
    unsafe {
        result = CryptProtectData(
            p_data_in,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            p_data_out
        );
    }

    if result.0 == 1 {
        let output;
        unsafe {
            let encrypted = std::slice::from_raw_parts(p_data_out.pb_data, (p_data_out.cb_data) as _);
            output = hex::encode(encrypted);
            LocalFree(p_data_out.pb_data as _);
        }
        Ok(output)
    } else {
        Err(WinEncryptError)
    }
}

#[cfg(test)]
mod tests {
    use crate::{decrypt, encrypt};

    #[test]
    fn it_works() {
        let input = "veni, vidi, vici";
        let encrypted = encrypt(input).unwrap();
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(input, decrypted);
    }
}
