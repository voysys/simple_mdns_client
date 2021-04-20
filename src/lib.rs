use std::{
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender},
    thread::{self, JoinHandle},
    time::Duration,
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

pub fn send_request(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    let prefer_unicast = false;
    builder.add_question(
        "OdenConfigurator._oden_configurator._tcp.local",
        prefer_unicast,
        dns_parser::QueryType::SRV,
        dns_parser::QueryClass::IN,
    );
    let packet_data = builder.build().unwrap();

    let addr = SocketAddr::new(MULTICAST_ADDR.into(), MULTICAST_PORT);

    socket.send_to(&packet_data, addr).ok();

    Ok(())
}

pub struct MdnsClient {
    exit_tx: SyncSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl MdnsClient {
    pub fn new() -> Result<MdnsClient, Box<dyn Error>> {
        let socket = create_socket()?;

        socket.set_multicast_loop_v4(false)?;
        socket.join_multicast_v4(&MULTICAST_ADDR, &ADDR_ANY)?;

        let (exit_tx, exit_rx) = sync_channel(0);

        let thread = thread::spawn(move || loop {
            match exit_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    send_request(&socket).ok();
                }
            }
        });

        Ok(MdnsClient {
            exit_tx,
            thread: Some(thread),
        })
    }
}

impl Drop for MdnsClient {
    fn drop(&mut self) {
        self.exit_tx.send(()).ok();
        self.thread.take().map(JoinHandle::join);
    }
}
