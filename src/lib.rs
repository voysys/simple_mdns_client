use dns_parser::{rdata::Srv, Packet, RData, ResourceRecord};
use std::{
    collections::HashMap,
    error::Error,
    io::{self},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        mpsc::{sync_channel, RecvTimeoutError, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(not(target_os = "windows"))]
use net2::unix::UnixUdpBuilderExt;

const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;

#[cfg(not(target_os = "windows"))]
fn create_socket() -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .reuse_port(true)?
        .bind((ADDR_ANY, MULTICAST_PORT))
}

#[cfg(target_os = "windows")]
fn create_socket() -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .bind((ADDR_ANY, MULTICAST_PORT))
}

pub fn send_request(socket: &UdpSocket, service: &str) -> Result<(), Box<dyn Error>> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    let prefer_unicast = false;
    builder.add_question(
        service,
        prefer_unicast,
        dns_parser::QueryType::SRV,
        dns_parser::QueryClass::IN,
    );
    let packet_data = builder.build().unwrap();

    let addr = SocketAddr::new(MULTICAST_ADDR.into(), MULTICAST_PORT);

    let res = socket.send_to(&packet_data, addr);

    log::debug!("Sending query: {:?}", res);

    Ok(())
}

pub fn handle_response(
    packet: &Packet,
    from: SocketAddr,
    service: &str,
    database: &Mutex<HashMap<Service, ServiceRecord>>,
) {
    log::debug!("{:?} => {:#?}", from, packet);

    if packet.header.query {
        return;
    }

    let mut database = database.lock().unwrap();

    for answer in &packet.answers {
        if let ResourceRecord {
            name,
            data: RData::SRV(Srv { target, port, .. }),
            ..
        } = answer
        {
            if name.to_string() == service {
                let service = Service {
                    host: target.to_string(),
                    port: *port,
                };

                database
                    .entry(service)
                    .and_modify(|e| e.last_seen_time = Instant::now())
                    .or_insert_with(|| ServiceRecord {
                        last_seen_time: Instant::now(),
                        addresses: Vec::new(),
                    });
            }
        }
    }
}

pub fn recive_response(
    socket: &UdpSocket,
    service: &str,
    database: &Mutex<HashMap<Service, ServiceRecord>>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer: [u8; 2048] = [0; 2048];

    loop {
        let (count, from) = socket.recv_from(&mut buffer)?;

        match dns_parser::Packet::parse(&buffer[..count]) {
            Ok(packet) => handle_response(&packet, from, service, database),
            Err(e) => log::warn!("{}", e),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Service {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
pub struct ServiceRecord {
    last_seen_time: Instant,
    addresses: Vec<SocketAddr>,
}

pub struct MdnsClient {
    database: Arc<Mutex<HashMap<Service, ServiceRecord>>>,
    exit_tx: SyncSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl MdnsClient {
    pub fn new(service: &str) -> Result<MdnsClient, Box<dyn Error>> {
        let database = Arc::new(Mutex::new(HashMap::new()));

        let socket = create_socket()?;

        socket.set_multicast_loop_v4(true)?;
        socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::new(0, 0, 0, 0))?;
        socket.set_nonblocking(true)?;

        let (exit_tx, exit_rx) = sync_channel(0);

        let thread = thread::spawn({
            let service = service.to_string();
            let database = database.clone();

            move || loop {
                match exit_rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        send_request(&socket, &service).ok();
                        recive_response(&socket, &service, &database).ok();
                    }
                }
            }
        });

        Ok(MdnsClient {
            database,
            exit_tx,
            thread: Some(thread),
        })
    }

    pub fn get_services(&self) -> Vec<(Service, ServiceRecord)> {
        self.database
            .lock()
            .unwrap()
            .iter()
            .map(|(service, record)| (service.clone(), record.clone()))
            .collect()
    }
}

impl Drop for MdnsClient {
    fn drop(&mut self) {
        self.exit_tx.send(()).ok();
        self.thread.take().map(JoinHandle::join);
    }
}
