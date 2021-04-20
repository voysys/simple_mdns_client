use mdns_client::MdnsClient;
use std::{env, error::Error, thread, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let mdns = MdnsClient::new("OdenConfigurator._oden_configurator._tcp.local")?;

    loop {
        println!("{:#?}", mdns.get_services());
        thread::sleep(Duration::from_millis(2000));
    }
}
