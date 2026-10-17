#![forbid(unsafe_code)]

mod dhcp;
mod dns;
mod http;
mod nm;
mod passphrase;
mod qr;
mod secret;
mod sockets;
mod ssid;
mod state;

fn main() {
    println!("wifi-connect {}", env!("CARGO_PKG_VERSION"));
}
