use std::{fs::{self, File}, writeln};
use std::io::{BufWriter, Write};

fn main() {

  // Encrypt the string "veni vidi vici"...
	let file = File::create("token.txt").unwrap();
	let mut buffer = BufWriter::new(&file);
	// And store it in a file for later use...
	let encrypted = win_crypto::encrypt("veni vidi vici").unwrap();
	writeln!(buffer, "{}", encrypted).unwrap(); // Just for posterity, added a newline to it as well
	buffer.flush().unwrap();

	// Powershell code to generate a token that can be read this way
	// $pw = read-host "Enter Token" -AsSecureString
	// ConvertFrom-SecureString $pw | out-file token.txt

	// Now retrieve it when we need it
	let read_file = fs::read_to_string("token.txt").unwrap();
	println!("Here is the encrypted string:\n{}", read_file.trim_end());
	let decrypted = win_crypto::decrypt(read_file.trim_end()).unwrap(); // Ensure newlines aren't sent to the decrypt function
	println!("Here is the decrypted string: {}", decrypted);

	// Or for reading from powershell
	// [PSCredential]::new('user', (gc token.txt | ConvertTo-SecureString)).GetNetworkCredential().Password

}
