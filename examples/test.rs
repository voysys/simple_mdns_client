use simple_mdns_client::MdnsClient;
use std::{error::Error, thread, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let mdns = MdnsClient::new("libmdns Web Server._http._tcp.local")?;

    loop {
        println!("{:#?}", mdns.get_services());
        thread::sleep(Duration::from_millis(2000));
    }
}
