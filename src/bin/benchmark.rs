use std::{
    fs::{self, File},
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

fn benchmark_tls() -> ([usize; 3], String) {
    let start_client_init = Instant::now();

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

    let time_client_init = start_client_init.elapsed();
    let start_server_init = Instant::now();

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

    let time_server_init = start_server_init.elapsed();

    let server_name = rustls::ServerName::try_from(server_domain_name).expect("Invalid DNS name");

    let start_client_hello = Instant::now();

    // Snd client hello
    let mut cl_tls_conn = ClientConnection::new(client_config, server_name).unwrap();
    let mut tls_buf = vec![];
    let m1_len = cl_tls_conn.write_tls(&mut tls_buf).unwrap();

    let time_client_hello = start_client_hello.elapsed();
    let start_server_hello = Instant::now();

    // Rcv client hello + Snd server hello
    let mut sv_tls_conn = ServerConnection::new(server_config.clone()).unwrap();
    sv_tls_conn.read_tls(&mut tls_buf.as_slice()).unwrap();
    sv_tls_conn.process_new_packets().unwrap();
    let mut tls_buf = vec![];
    let m2_len = sv_tls_conn.write_tls(&mut tls_buf).unwrap();

    let time_server_hello = start_server_hello.elapsed();
    let start_client_key_share = Instant::now();

    // Rcv server hello + Client KE + Snd "Hello World"
    cl_tls_conn.read_tls(&mut tls_buf.as_slice()).unwrap();
    cl_tls_conn.process_new_packets().unwrap();
    let text = "Hello, World!";
    cl_tls_conn
        .writer()
        .write(text.as_bytes())
        .expect("Should send message");
    let mut tls_buf = vec![];
    let m3_len = cl_tls_conn.write_tls(&mut tls_buf).unwrap();

    let time_client_key_share = start_client_key_share.elapsed();
    let start_server_finished = Instant::now();

    sv_tls_conn.read_tls(&mut tls_buf.as_slice()).unwrap();
    sv_tls_conn.process_new_packets().unwrap();
    let mut result = [0; 13];
    sv_tls_conn
        .reader()
        .read(&mut result)
        .expect("Should receive message");

    let time_server_finished = start_server_finished.elapsed();

    let result = String::from_utf8(result.to_vec()).unwrap();

    assert!(result == text);

    let msg_len = [m1_len, m2_len, m3_len];
    let times = [
        time_client_init,
        time_server_init,
        time_client_hello,
        time_server_hello,
        time_client_key_share,
        time_server_finished,
    ]
    .map(|t| t.as_micros().to_string())
    .join(",");

    return (msg_len, times);
}

fn main() {
    let (msg_len, _) = benchmark_tls();
    println!("TLS messages length: {msg_len:?}");
    println!("Total: {}", msg_len.iter().fold(0, |s, x| s + x));

    let mut csv = File::create("tls_alone.csv").expect("Should be able to write file");
    csv.write_all(
        "client_init,server_init,client_hello,server_hello,client_key_share,server_finished\n"
            .as_bytes(),
    )
    .unwrap();

    for i in 1..50000 {
        let (_, times) = benchmark_tls();
        csv.write_all(format!("{times}\n").as_bytes()).unwrap();
        if i % 5000 == 0 {
            println!("{i}");
        }
    }
}
