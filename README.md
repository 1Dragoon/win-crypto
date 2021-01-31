## win_crypto

A simple wrapper for Microsoft Windows DPAPI for encrypting and decrypting strings for data at rest. Use it in cases where you have password authentication but don't want to keep plaintext passwords in your code. If you've ever used powershell to store passwords this way, this should be familiar:

```powershell
# create a token
$pw = read-host "Enter Token" -AsSecureString
ConvertFrom-SecureString $pw | out-file token.txt
# read from it
[PSCredential]::new('user', (gc token.txt | ConvertTo-SecureString)).GetNetworkCredential().Password
```

This crate does the same thing, only in Rust :)

## Getting started

Start by adding the following to your Cargo.toml file:

```toml
[dependencies]
win_crypto = { git = "https://github.com/1Dragoon/win_crypto" }
```

Call it from your code:

```rust
use std::{fs::{self, File}, writeln};
use std::io::{BufWriter, Write};

// Encrypt the string "veni vidi vici"...
let file = File::create("token.txt").unwrap();
let mut buffer = BufWriter::new(&file);
// And store it in a file for later use...
let encrypted = win_crypto::encrypt("veni vidi vici").unwrap();
writeln!(buffer, "{}", encrypted).unwrap(); // Just for posterity, added a newline to it as well
buffer.flush().unwrap();
// Now retrieve it when we need it
let read_file = fs::read_to_string("token.txt").unwrap();
println!("Here is the encrypted string:\n{}", read_file.trim_end());
let decrypted = win_crypto::decrypt(read_file.trim_end()).unwrap(); // Ensure newlines aren't sent to the decrypt function
println!("Here is the decrypted string: {}", decrypted);
```

Have fun!