use std::{
    fs,
    io::{BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream},
    sync::Arc,
};

use rustls::ClientConnection;

fn main() {
    // Create the CA root store, add the CA certificate to it
    let mut root_store = rustls::RootCertStore::empty();

    let root_crt_file = fs::File::open("openssl/rootCA.crt").unwrap();
    let mut br = BufReader::new(root_crt_file);

    let cert_u8 = rustls_pemfile::certs(&mut br).unwrap().pop().unwrap();

    let cert = rustls::Certificate(cert_u8);

    root_store.add(&cert).unwrap();

    println!("{}", root_store.len());

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let server_name = rustls::ServerName::try_from("test.localhost").expect("invalid DNS name");

    let mut tls_conn = ClientConnection::new(config, server_name).unwrap();

    let server_ip = "127.0.0.1:7878";
    let mut socket = TcpStream::connect(server_ip).unwrap();

    let mut stream = rustls::Stream::new(&mut tls_conn, &mut socket);

    if stream.conn.is_handshaking() {
        println!("Handshaking in progress.");
    }

    if stream.conn.wants_write() {
        println!("Wants writing.");
    }

    if stream.conn.wants_read() {
        println!("Wants reading.");
    }

    match stream.conn.complete_io(&mut stream.sock) {
        Ok(res) => {
            println!("Handshake done.");
            println!("{res:?}");
        }
        Err(err) => {
            println!("{err:#?}");
            return;
        }
    };

    if stream.conn.is_handshaking() {
        println!("Handshaking in progress.");
    }

    if stream.conn.wants_write() {
        println!("Wants writing.");
    }

    if stream.conn.wants_read() {
        println!("Wants reading.");
    }

    let res = stream.write(&[42, 0]).unwrap();
    println!("{res}");

    if stream.conn.is_handshaking() {
        println!("Handshaking in progress.");
    }

    if stream.conn.wants_write() {
        println!("Wants writing.");
    }

    if stream.conn.wants_read() {
        println!("Wants reading.");
    }

    // let req = "\r\n\r\n";
    // socket.write_all(req.as_bytes()).unwrap();

    // let mut res = String::new();
    // socket.read_to_string(&mut res).unwrap();

    // println!("{res}");
}
