use std::{
    fs,
    io::{BufReader, Read, Write},
    sync::Arc,
    time::Instant,
};

use rustls::{ClientConnection, ServerConnection};

fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, std::io::Error> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    Ok(certs)
}

fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, std::io::Error> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("Could not find private key in {filename}"),
    ))
}

fn benchmark_tls() {
    println!("Benckmarking TLS alone.");

    // CLIENT INIT
    let root_ca_filepath = "openssl/rootCA.crt";
    let server_domain_name = "opaque.localhost";

    let mut root_store = rustls::RootCertStore::empty();

    let root_crt_file =
        fs::File::open(root_ca_filepath).expect("Could not open CA certificate file");

    let mut br = BufReader::new(root_crt_file);

    let cert_u8 = rustls_pemfile::certs(&mut br)
        .expect("Parsing CA certificate failed")
        .pop()
        .expect("CA certificate file is empty");

    let cert = rustls::Certificate(cert_u8);

    root_store
        .add(&cert)
        .expect("Failed to add CA certificate to root store");

    let client_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    // SERVER INIT
    let server_cert = "openssl/server.crt";
    let server_priv_key = "openssl/server.key";

    let certs = load_certs(server_cert).expect("Should load server certificate");
    let private_key = load_private_key(server_priv_key).expect("Should load server private key");

    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("Bad certificates or private key"),
    );

    // CONNECTION
    let server_name = rustls::ServerName::try_from(server_domain_name).expect("Invalid DNS name");
    let mut sv_tls_conn = ServerConnection::new(server_config.clone()).unwrap();
    let mut cl_tls_conn = ClientConnection::new(client_config, server_name).unwrap();

    let start = Instant::now();

    // FIRST MESSAGE (CLIENT HELLO)
    let mut tls_buf = vec![];
    let m1_len = cl_tls_conn.write_tls(&mut tls_buf).unwrap();
    sv_tls_conn.read_tls(&mut tls_buf.as_slice()).unwrap();
    sv_tls_conn.process_new_packets().unwrap();

    // SECOND MESSAGE (SERVER HELLO)
    let mut tls_buf = vec![];
    let m2_len = sv_tls_conn.write_tls(&mut tls_buf).unwrap();
    cl_tls_conn.read_tls(&mut tls_buf.as_slice()).unwrap();
    cl_tls_conn.process_new_packets().unwrap();

    // THIRD MESSAGE
    let text = "Hello, World!";

    cl_tls_conn
        .writer()
        .write(text.as_bytes())
        .expect("Should send message");

    let mut tls_buf = vec![];
    let m3_len = cl_tls_conn.write_tls(&mut tls_buf).unwrap();
    sv_tls_conn.read_tls(&mut tls_buf.as_slice()).unwrap();
    sv_tls_conn.process_new_packets().unwrap();

    let mut result = [0; 50];

    sv_tls_conn
        .reader()
        .read(&mut result)
        .expect("Should receive message");

    let rtt = start.elapsed();

    let result = String::from_utf8(result.to_vec()).unwrap();
    println!("Received: {result}");

    println!("Time for handshake + msg: {:#?}", rtt);
    println!("Messages length in bytes: {m1_len}, {m2_len}, {m3_len}");
    println!("Total: {} bytes", m1_len + m2_len + m3_len);
}

fn main() {
    benchmark_tls();
}
