use std::{
    fs,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use rustls::ServerConnection;

pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn main() {
    let certs = load_certs("openssl/server.crt");
    let private_key = load_private_key("openssl/server.key");

    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("bad certificates/private key"),
    );

    let mut tls_conn = ServerConnection::new(config).unwrap();

    let server_ip = "127.0.0.1:7878";
    let listener = TcpListener::bind(server_ip).unwrap();

    let mut socket = listener.accept().unwrap().0;
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

    let mut buf: [u8; 2] = [0, 0];
    stream.read(&mut buf).unwrap();

    println!("{buf:#?}");
}

// fn handle_connection(mut stream: TcpStream) {
//     let buf_reader = BufReader::new(&mut stream);
//     let http_request: Vec<_> = buf_reader
//         .lines()
//         .map(|result| result.unwrap())
//         .take_while(|line| !line.is_empty())
//         .collect();

//     let response = "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\nHello World!";

//     stream.write_all(response.as_bytes()).unwrap();
// }
