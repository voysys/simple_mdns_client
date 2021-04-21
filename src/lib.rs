use dns_parser::{
    rdata::{Srv, A},
    Packet, RData, ResourceRecord,
};
use if_addrs::IfAddr;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    io,
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

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;

#[cfg(not(target_os = "windows"))]
fn create_socket(addr: Ipv4Addr) -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .reuse_port(true)?
        .bind((addr, MULTICAST_PORT))
}

#[cfg(target_os = "windows")]
fn create_socket(addr: Ipv4Addr) -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .bind((addr, MULTICAST_PORT))
}

fn send_request(socket: &UdpSocket, service: &str) {
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

    socket.send_to(&packet_data, addr).ok();
}

fn handle_response(
    packet: &Packet,
    service: &str,
    database: &Mutex<HashMap<Service, ServiceRecord>>,
) {
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
                        addresses: HashSet::new(),
                    });
            }
        }
    }

    for answer in &packet.answers {
        if let ResourceRecord {
            name,
            data: RData::A(A(addr)),
            ..
        } = answer
        {
            for (k, v) in database.iter_mut() {
                if k.host == name.to_string() {
                    v.addresses.insert(*addr);
                }
            }
        }
    }
}

fn recive_response(
    socket: &UdpSocket,
    service: &str,
    database: &Mutex<HashMap<Service, ServiceRecord>>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer: [u8; 2048] = [0; 2048];

    loop {
        let count = socket.recv(&mut buffer)?;

        if let Ok(packet) = dns_parser::Packet::parse(&buffer[..count]) {
            handle_response(&packet, service, database);
        }
    }
}

fn remove_old_entries(database: &Mutex<HashMap<Service, ServiceRecord>>) {
    let mut database = database.lock().unwrap();
    database.retain(|_, v| v.last_seen_time.elapsed() < Duration::from_secs(5));
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ServiceRecord {
    pub last_seen_time: Instant,
    pub addresses: HashSet<Ipv4Addr>,
}

pub struct MdnsClient {
    database: Arc<Mutex<HashMap<Service, ServiceRecord>>>,
    exit_tx: SyncSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl MdnsClient {
    pub fn new(service: &str) -> Result<MdnsClient, Box<dyn Error>> {
        let database = Arc::new(Mutex::new(HashMap::new()));

        let mut sockets = Vec::new();

        for iface in if_addrs::get_if_addrs()?
            .into_iter()
            .filter(|i| !i.addr.is_loopback())
            .filter_map(|i| {
                if let IfAddr::V4(v4_addr) = i.addr {
                    Some(v4_addr)
                } else {
                    None
                }
            })
        {
            let socket = create_socket(iface.ip)?;

            socket.set_multicast_loop_v4(true)?;
            socket.join_multicast_v4(&MULTICAST_ADDR, &iface.ip)?;
            socket.set_nonblocking(true)?;

            sockets.push(socket);
        }

        let (exit_tx, exit_rx) = sync_channel(0);

        let thread = thread::spawn({
            let service = service.to_string();
            let database = database.clone();

            move || loop {
                match exit_rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        for socket in &sockets {
                            send_request(&socket, &service).ok();
                            recive_response(&socket, &service, &database).ok();
                        }

                        remove_old_entries(&database);
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
