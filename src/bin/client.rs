use std::{
    fs,
    io::{self, BufReader, Write},
    net::TcpStream,
    sync::Arc,
};

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use opaque_over_tls::{read_msg, send_msg};
use rand::rngs::OsRng;
use rustls::ClientConnection;

struct OpaqueCipherSuite;
impl opaque_ke::CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

struct ClientApp {
    tls_conn: ClientConnection,
    tls_socket: TcpStream,
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

        let mut tls_conn = ClientConnection::new(client_config, server_name).unwrap();

        let mut tls_socket = TcpStream::connect(server_ip).unwrap();

        while tls_conn.is_handshaking() {
            tls_conn.complete_io(&mut tls_socket).unwrap();
        }

        println!("TLS handshake done.");

        let tcp_socket = TcpStream::connect(server_ip).unwrap();

        ClientApp {
            tls_conn,
            tls_socket,
            tcp_socket,
        }
    }
}

// Method impl
impl ClientApp {
    fn register(&mut self) {
        let username = "Alice";
        let password = "password123";

        self.tcp_socket.write_all(&[1]).unwrap();

        let mut client_rng = OsRng;
        let client_reg_start_res =
            ClientRegistration::<OpaqueCipherSuite>::start(&mut client_rng, password.as_bytes())
                .unwrap();

        let mut tls_stream = rustls::Stream::new(&mut self.tls_conn, &mut self.tls_socket);

        send_msg(&mut tls_stream, username.as_bytes());

        send_msg(
            &mut tls_stream,
            client_reg_start_res.message.serialize().as_slice(),
        );

        let buf = read_msg(&mut tls_stream);

        println!("Read {}", buf.len());
        println!("{:#?}", String::from_utf8_lossy(&buf));

        let server_reg_res = RegistrationResponse::<OpaqueCipherSuite>::deserialize(&buf).unwrap();

        let client_reg_fin_res = client_reg_start_res
            .state
            .finish(
                &mut client_rng,
                password.as_bytes(),
                server_reg_res,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();

        send_msg(
            &mut tls_stream,
            client_reg_fin_res.message.serialize().as_slice(),
        );

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

    // TODO error handling
    fn login(&mut self) {
        let username = "Alice";
        let password = "password123";

        self.tcp_socket.write_all(&[2]).unwrap();
        let mut tls_stream = rustls::Stream::new(&mut self.tls_conn, &mut self.tls_socket);

        send_msg(&mut tls_stream, username.as_bytes());

        let mut client_rng = OsRng;
        let client_login_start_res =
            ClientLogin::<OpaqueCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

        send_msg(
            &mut tls_stream,
            client_login_start_res.message.serialize().as_slice(),
        );

        let server_res = read_msg(&mut tls_stream);
        let credential_res =
            CredentialResponse::<OpaqueCipherSuite>::deserialize(&server_res).unwrap();

        let client_login_fin_res = client_login_start_res
            .state
            .finish(
                password.as_bytes(),
                credential_res,
                ClientLoginFinishParameters::default(),
            )
            .unwrap();

        send_msg(
            &mut tls_stream,
            client_login_fin_res.message.serialize().as_slice(),
        );

        println!("{:?}", client_login_fin_res.session_key.as_slice());

        // TODO use the session key to have the server echo the client

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

    fn exit(&mut self) {
        self.tcp_socket.write_all(&[3]).unwrap();
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
                app.exit();
                break;
            }
        }
    }
}
