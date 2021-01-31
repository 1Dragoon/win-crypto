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
use windows::{Error, ErrorCode};

pub fn decrypt(encrypted: &str) -> Result<String, windows::Error> {
    let mut et_bytes = hex::decode(encrypted).unwrap();

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
        Err(Error::new(ErrorCode::default(), "Failed to decrypt."))
    }
}

pub fn encrypt(input: &str) -> Result<String, windows::Error> {
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
        Err(Error::new(ErrorCode::default(), "Failed to encrypt."))
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
