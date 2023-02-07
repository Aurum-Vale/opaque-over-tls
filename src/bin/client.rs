use std::{
    fs,
    io::{self, BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
};

use rustls::ClientConnection;

struct ClientApp {
    tls_conn: ClientConnection,
    tcp_socket: TcpStream,
}

// Static impl
impl ClientApp {
    // TODO Unwrap management
    fn init() -> ClientApp {
        let root_ca_filepath = "openssl/rootCA.crt";
        let server_domain_name = "opaque.localhost";
        let server_ip = "127.0.0.1:7878";

        // Create the CA root store, add the CA certificate to it
        let mut root_store = rustls::RootCertStore::empty();

        let root_crt_file = fs::File::open(root_ca_filepath).unwrap();
        let mut br = BufReader::new(root_crt_file);

        let cert_u8 = rustls_pemfile::certs(&mut br).unwrap().pop().unwrap();

        let cert = rustls::Certificate(cert_u8);

        root_store.add(&cert).unwrap();

        //println!("{}", root_store.len());

        let client_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        let server_name =
            rustls::ServerName::try_from(server_domain_name).expect("invalid DNS name");

        let tls_conn = ClientConnection::new(client_config, server_name).unwrap();

        let tcp_socket = TcpStream::connect(server_ip).unwrap();

        ClientApp {
            tls_conn,
            tcp_socket,
        }
    }
}

// Method impl
impl ClientApp {
    fn register(&mut self) {}

    fn login(&mut self) {
        let mut stream = rustls::Stream::new(&mut self.tls_conn, &mut self.tcp_socket);

        stream.write_all(b"Hello World").unwrap();

        let mut buf: [u8; 32] = [0; 32];
        let r = stream.read(&mut buf).unwrap();

        println!("Read {r}");
        println!("{:#?}", String::from_utf8_lossy(&buf[..r]));

        // let pc = &stream.conn.peer_certificates().unwrap()[0].0;
        //
        // let pc = x509_parser::parse_x509_certificate(pc).unwrap().1;
        //
        // let req = "\r\n\r\n";
        // socket.write_all(req.as_bytes()).unwrap();
        // let mut res = String::new();
        // socket.read_to_string(&mut res).unwrap();
        //
        // println!("Signature: {:02x?}", pc.signature_value.data);
        // println!(
        //     "Subject: {:?}",
        //     pc.tbs_certificate
        //         .subject()
        //         .iter_common_name()
        //         .next()
        //         .unwrap()
        //         .as_str()
        //         .unwrap()
        // );
        // println!(
        //     "Authority: {:?}",
        //     pc.tbs_certificate
        //         .issuer()
        //         .iter_common_name()
        //         .next()
        //         .unwrap()
        //         .as_str()
        //         .unwrap()
        // );
        // println!("Public key: {:02x?}", pc.tbs_certificate.public_key().raw);
    }
}

enum MainMenuChoice {
    Register,
    Login,
    Exit,
}

fn main_menu() -> MainMenuChoice {
    println!("1. Register a new user");
    println!("2. Login");
    println!("3. Exit");

    let mut buf = String::new();

    if let Err(_) = io::stdin().read_line(&mut buf) {
        return MainMenuChoice::Exit;
    }

    let choice = match buf.trim().parse::<u8>() {
        Ok(x) => x,
        Err(_) => {
            return MainMenuChoice::Exit;
        }
    };

    match choice {
        1 => MainMenuChoice::Register,
        2 => MainMenuChoice::Login,
        _ => MainMenuChoice::Exit,
    }
}

fn main() {
    let mut app = ClientApp::init();

    loop {
        match main_menu() {
            MainMenuChoice::Register => app.register(),
            MainMenuChoice::Login => app.login(),
            MainMenuChoice::Exit => {
                return;
            }
        }
    }
}
