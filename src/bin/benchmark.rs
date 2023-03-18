use argon2::Argon2;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ServerLogin, ServerLoginStartParameters,
    ServerRegistration,
};
use rand::rngs::OsRng;
use rustls::{ClientConnection, ServerConnection};
use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::Path,
    sync::Arc,
    time::Instant,
};

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

pub struct OpaqueCipherSuite;
impl opaque_ke::CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

fn benchmark_opaque() -> ([usize; 3], String) {
    // Credentials and setup data retrieval (untimed)
    // All files are used from the main program
    let server_setup_data = fs::read(Path::new("credentials/server.setup")).unwrap();
    let client_username = "benchmark";
    let client_password = "benchmark";
    let bin_credentials = fs::read(Path::new("credentials/benchmark.bin")).unwrap();
    let server_password = ServerRegistration::<OpaqueCipherSuite>::deserialize(&bin_credentials)
        .expect("Credentials files should be deserializable");

    // Server init
    let start_server_init = Instant::now();

    let server_setup = opaque_ke::ServerSetup::<
        OpaqueCipherSuite,
        opaque_ke::keypair::PrivateKey<opaque_ke::Ristretto255>,
    >::deserialize(&server_setup_data)
    .expect("OPAQUE server setup file should be deserializable");

    let time_server_init = start_server_init.elapsed();

    // Credential Request
    let start_cred_req = Instant::now();

    let mut client_rng = OsRng;
    let client_login_start_res =
        ClientLogin::<OpaqueCipherSuite>::start(&mut client_rng, client_password.as_bytes())
            .unwrap();

    let time_cred_req = start_cred_req.elapsed();
    let m1_len = client_login_start_res.message.serialize().len();

    // Credential Response
    let start_cred_res = Instant::now();

    let mut server_rng = OsRng;
    let server_login_start_res = ServerLogin::<OpaqueCipherSuite>::start(
        &mut server_rng,
        &server_setup,
        Some(server_password),
        client_login_start_res.message,
        client_username.as_bytes(),
        ServerLoginStartParameters::default(),
    )
    .unwrap();

    let time_cred_res = start_cred_res.elapsed();
    let m2_len = server_login_start_res.message.serialize().len();

    // Credentials Finalization, Client
    let start_cl_fin = Instant::now();

    let client_login_fin_res = client_login_start_res
        .state
        .finish(
            client_password.as_bytes(),
            server_login_start_res.message,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let time_cl_fin = start_cl_fin.elapsed();
    let m3_len = client_login_fin_res.message.serialize().len();

    // Credentials Finalization, Server
    let start_sv_fin = Instant::now();

    let server_login_fin_res = server_login_start_res
        .state
        .finish(client_login_fin_res.message)
        .unwrap();

    let time_sv_fin = start_sv_fin.elapsed();

    let server_session_key = server_login_fin_res.session_key;
    let client_session_key = client_login_fin_res.session_key;

    assert!(server_session_key == client_session_key);

    let msg_len = [m1_len, m2_len, m3_len];
    let times = [
        time_server_init,
        time_cred_req,
        time_cred_res,
        time_cl_fin,
        time_sv_fin,
    ]
    .map(|t| t.as_micros().to_string())
    .join(",");

    return (msg_len, times);
}

fn main() {
    // let (msg_len, _) = benchmark_tls();
    // println!("TLS messages length: {msg_len:?}");
    // println!("Total: {}", msg_len.iter().fold(0, |s, x| s + x));
    //
    // let mut csv = File::create("tls_alone.csv").expect("Should be able to write file");
    // csv.write_all(
    //     "client_init,server_init,client_hello,server_hello,client_key_share,server_finished\n"
    //         .as_bytes(),
    // )
    // .unwrap();
    //
    // for i in 1..50000 {
    //     let (_, times) = benchmark_tls();
    //     csv.write_all(format!("{times}\n").as_bytes()).unwrap();
    //     if i % 5000 == 0 {
    //         println!("{i}");
    //     }
    // }

    let (msg_len, _) = benchmark_opaque();
    println!("OPAQUE messages length: {msg_len:?}");
    println!("Total: {}", msg_len.iter().fold(0, |s, x| s + x));

    let mut csv = File::create("tls_alone.csv").expect("Should be able to write file");
    csv.write_all("server_init,cred_req,cred_res,cl_fin,sv_fin\n".as_bytes())
        .unwrap();

    for i in 1..1000 {
        let (_, times) = benchmark_opaque();
        csv.write_all(format!("{times}\n").as_bytes()).unwrap();
        if i % 5000 == 0 {
            println!("{i}");
        }
    }
}
