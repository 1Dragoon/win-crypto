fn main() {
	windows::build!(
			windows::win32::security::CryptUnprotectData
			windows::win32::security::CryptProtectData
			windows::win32::system_services::LocalFree
	);
}
