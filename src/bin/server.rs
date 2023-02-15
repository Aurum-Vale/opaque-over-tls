use std::{
    collections::HashMap,
    fs,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration};
use opaque_over_tls::{read_msg, send_msg};
use rustls::{ServerConfig, ServerConnection};

struct OpaqueCipherSuite;
impl opaque_ke::CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

struct Client {
    tls_conn: ServerConnection,
    tls_socket: TcpStream,
    tcp_socket: TcpStream,
}

struct ServerApp {
    tls_config: Arc<ServerConfig>,
    tcp_listener: TcpListener,
    opaque_setup: opaque_ke::ServerSetup<
        OpaqueCipherSuite,
        opaque_ke::keypair::PrivateKey<opaque_ke::Ristretto255>,
    >,
    credentials_map: HashMap<String, ServerRegistration<OpaqueCipherSuite>>,
}

// Static impl
impl ServerApp {
    fn init_tls() -> Arc<ServerConfig> {
        let server_cert = "openssl/server.crt";
        let server_priv_key = "openssl/server.key";

        let certs = Self::load_certs(server_cert);
        let private_key = Self::load_private_key(server_priv_key);

        Arc::new(
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .expect("bad certificates/private key"),
        )
    }

    fn init_listener() -> TcpListener {
        let server_ip = "127.0.0.1:7878";
        TcpListener::bind(server_ip).unwrap()
    }

    fn init_opaque() -> opaque_ke::ServerSetup<
        OpaqueCipherSuite,
        opaque_ke::keypair::PrivateKey<opaque_ke::Ristretto255>,
    > {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        opaque_ke::ServerSetup::<OpaqueCipherSuite>::new(&mut rng)
    }

    fn init_credentials() -> HashMap<String, ServerRegistration<OpaqueCipherSuite>> {
        HashMap::new()
    }

    // TODO Unwrap management
    fn init() -> ServerApp {
        let tls_config = Self::init_tls();
        let tcp_listener = Self::init_listener();
        let opaque_setup = Self::init_opaque();
        let credentials_map = Self::init_credentials();

        ServerApp {
            tcp_listener,
            tls_config,
            opaque_setup,
            credentials_map,
        }
    }

    fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
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
            match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file")
            {
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
}

// Method impl
impl ServerApp {
    fn accept_connection(&mut self) {
        let mut tls_socket = self.tcp_listener.accept().unwrap().0;

        let mut tls_conn = ServerConnection::new(self.tls_config.clone()).unwrap();

        while tls_conn.is_handshaking() {
            tls_conn.complete_io(&mut tls_socket).unwrap();
        }

        println!("TLS handshake done.");

        let tcp_socket = self.tcp_listener.accept().unwrap().0;

        let mut client = Client {
            tls_conn,
            tls_socket,
            tcp_socket,
        };

        loop {
            let mut buf_choice: [u8; 1] = [0];
            client.tcp_socket.read_exact(&mut buf_choice).unwrap();

            match buf_choice[0] {
                1 => self.register(&mut client),
                2 => self.login(&mut client),
                _ => break,
            }
        }
    }

    fn register(&mut self, client: &mut Client) {
        let mut tls_stream = rustls::Stream::new(&mut client.tls_conn, &mut client.tls_socket);

        let client_username = String::from_utf8(read_msg(&mut tls_stream)).unwrap();
        println!("{client_username}");

        let reg_req = read_msg(&mut tls_stream);
        println!("Read {}", reg_req.len());
        println!("{:#?}", String::from_utf8_lossy(&reg_req));

        let client_reg_req =
            RegistrationRequest::<OpaqueCipherSuite>::deserialize(&reg_req).unwrap();

        let server_reg_start_res = ServerRegistration::<OpaqueCipherSuite>::start(
            &self.opaque_setup,
            client_reg_req,
            client_username.as_bytes(),
        )
        .unwrap();

        send_msg(
            &mut tls_stream,
            server_reg_start_res.message.serialize().as_slice(),
        );

        let reg_upload = read_msg(&mut tls_stream);
        println!("Read {}", reg_upload.len());
        println!("{:#?}", String::from_utf8_lossy(&reg_upload));

        let registration_fin =
            RegistrationUpload::<OpaqueCipherSuite>::deserialize(&reg_upload).unwrap();

        let password_file = ServerRegistration::<OpaqueCipherSuite>::finish(registration_fin);

        self.credentials_map.insert(client_username, password_file);
    }

    fn login(&mut self, client: &mut Client) {
        let mut stream = rustls::Stream::new(&mut client.tls_conn, &mut client.tls_socket);

        let mut buf: [u8; 32] = [0; 32];
        let r = stream.read(&mut buf).unwrap();

        println!("Read {r}");
        println!("{:#?}", String::from_utf8_lossy(&buf[..r]));

        stream.write_all(&buf[..r]).unwrap();
    }
}

fn main() {
    let mut app = ServerApp::init();
    loop {
        app.accept_connection();
    }
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
