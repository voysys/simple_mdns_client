use std::{env, error::Error};

use mdns_client::MdnsClient;

fn main() -> Result<(), Box<dyn Error>> {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let mdns = MdnsClient::new()?;

    loop {}

    Ok(())
}
