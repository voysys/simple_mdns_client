use dns_parser::{
    rdata::{Srv, A},
    Packet, RData, ResourceRecord,
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
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

// DNS header flags
const OPCODE_QUERY: u16 = 0x0000;

struct DnsHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DnsHeader {
    fn new_query() -> Self {
        DnsHeader {
            id: 0,               // mDNS typically uses 0 for queries
            flags: OPCODE_QUERY, // Standard query
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.num_questions.to_be_bytes());
        bytes.extend_from_slice(&self.num_answers.to_be_bytes());
        bytes.extend_from_slice(&self.num_authorities.to_be_bytes());
        bytes.extend_from_slice(&self.num_additionals.to_be_bytes());
        bytes
    }
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in name.split('.') {
        bytes.push(part.len() as u8);
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes.push(0); // Terminate with null byte
    bytes
}

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

fn send_mdns_query(socket: &UdpSocket, service_name: &str) -> Result<(), Box<dyn Error>> {
    // Create DNS header
    let header = DnsHeader::new_query();

    // Build the query packet
    let mut packet = Vec::new();

    // Add header
    packet.extend(header.to_bytes());

    // Add question section
    packet.extend(encode_dns_name(service_name));

    // Add QTYPE (PTR = 12) and QCLASS (IN = 1) with QU bit set
    packet.extend_from_slice(&(12u16).to_be_bytes()); // QTYPE
    packet.extend_from_slice(&(1u16).to_be_bytes()); // QCLASS

    let mdns_addr = SocketAddrV4::new(MULTICAST_ADDR, MULTICAST_PORT);
    socket.send_to(&packet, mdns_addr)?;

    Ok(())
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
            if name.to_string().contains(service) {
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

fn receive_response(
    socket: &UdpSocket,
    service: &str,
    database: &Mutex<HashMap<Service, ServiceRecord>>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer: [u8; 2048] = [0; 2048];

    loop {
        let len = socket.recv(&mut buffer)?;

        if let Ok(packet) = dns_parser::Packet::parse(&buffer[..len]) {
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

        #[cfg(target_os = "windows")]
        {
            use if_addrs::IfAddr;

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
        }

        #[cfg(target_os = "linux")]
        {
            let socket = create_socket(Ipv4Addr::UNSPECIFIED)?;

            socket.set_multicast_loop_v4(true)?;
            socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
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
                            send_mdns_query(socket, &service).ok();
                            receive_response(socket, &service, &database).ok();
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
