# Simple mdns client

```rust
use simple_mdns_client::MdnsClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mdns = MdnsClient::new("libmdns Web Server._http._tcp.local")?;

    loop {
        println!("{:#?}", mdns.get_services());
        std::thread::sleep(std::time::Duration::from_millis(2000));
    }
}
```

Only testet to work with https://github.com/librespot-org/libmdns
