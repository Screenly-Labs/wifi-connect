#![forbid(unsafe_code)]

mod dhcp;
mod dns;
mod passphrase;
mod qr;
mod secret;
mod sockets;
mod ssid;

fn main() {
    println!("wifi-connect {}", env!("CARGO_PKG_VERSION"));
}
