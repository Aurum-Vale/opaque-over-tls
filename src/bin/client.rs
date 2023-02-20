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
use opaque_over_tls::{increment_nonce, read_msg, send_msg, ClientQuery, OpaqueCipherSuite};
use rand::rngs::OsRng;
use rustls::ClientConnection;

struct ClientApp {
    tls_conn: ClientConnection,
    tls_socket: TcpStream,
    tcp_socket: TcpStream,
}

// Static impl
impl ClientApp {
    /// Initialise the client application.
    /// Manages TLS configuration and TCP connections.
    /// Tries to connect to the server application.
    fn init() -> ClientApp {
        let root_ca_filepath = "openssl/rootCA.crt";
        let server_domain_name = "opaque.localhost";
        let server_ip = "127.0.0.1:7878";

        // Create the CA root store, add the CA certificate to it
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

        let server_name =
            rustls::ServerName::try_from(server_domain_name).expect("Invalid DNS name");

        // Create the TLS connection (only TLS-related stuff, not TCP)
        let mut tls_conn = ClientConnection::new(client_config, server_name)
            .expect("Failure to create TLS connection");

        let mut tls_socket =
            TcpStream::connect(server_ip).expect("TCP connection to server failed");

        while tls_conn.is_handshaking() {
            tls_conn
                .complete_io(&mut tls_socket)
                .expect("Should finish TLS handshake");
        }

        println!("TLS handshake done.");

        // Unencrypted TCP socket
        let tcp_socket =
            TcpStream::connect(server_ip).expect("Failed connection to plain TCP with server");

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
        let mut username = String::new();
        let mut password = String::new();

        println!("Username:");
        io::stdin()
            .read_line(&mut username)
            .expect("Could not read username stdio");
        println!("Password:");
        io::stdin()
            .read_line(&mut password)
            .expect("Could not read password from stdio");

        let username = username.trim();
        let password = password.trim();

        self.tcp_socket
            .write_all(&[ClientQuery::Registration as u8])
            .expect("Could not send to TCP");

        let mut client_rng = OsRng;
        let client_reg_start_res =
            ClientRegistration::<OpaqueCipherSuite>::start(&mut client_rng, password.as_bytes())
                .expect("Failed to create Client Registration request");

        let mut tls_stream = rustls::Stream::new(&mut self.tls_conn, &mut self.tls_socket);

        send_msg(&mut tls_stream, username.as_bytes()).unwrap();

        send_msg(
            &mut tls_stream,
            client_reg_start_res.message.serialize().as_slice(),
        )
        .unwrap();

        let buf = read_msg(&mut tls_stream).unwrap();

        if buf.len() == 0 {
            println!("Registration aborted (user already exists)");
            return;
        }

        println!("Read {}", buf.len());
        println!("{:#?}", String::from_utf8_lossy(&buf));

        let server_reg_res = RegistrationResponse::<OpaqueCipherSuite>::deserialize(&buf)
            .expect("Invalid server response for Registration");

        let client_reg_fin_res = client_reg_start_res
            .state
            .finish(
                &mut client_rng,
                password.as_bytes(),
                server_reg_res,
                ClientRegistrationFinishParameters::default(),
            )
            .expect("Could not finish Client Registration");

        send_msg(
            &mut tls_stream,
            client_reg_fin_res.message.serialize().as_slice(),
        )
        .unwrap();
    }

    // TODO error handling
    fn login(&mut self) {
        let mut username = String::new();
        let mut password = String::new();

        println!("Username:");
        io::stdin().read_line(&mut username).unwrap();
        println!("Password:");
        io::stdin().read_line(&mut password).unwrap();

        let username = username.trim();
        let password = password.trim();

        self.tcp_socket
            .write_all(&[ClientQuery::Login as u8])
            .unwrap();
        let mut tls_stream = rustls::Stream::new(&mut self.tls_conn, &mut self.tls_socket);

        send_msg(&mut tls_stream, username.as_bytes()).unwrap();

        let mut client_rng = OsRng;
        let client_login_start_res =
            ClientLogin::<OpaqueCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

        send_msg(
            &mut tls_stream,
            client_login_start_res.message.serialize().as_slice(),
        )
        .unwrap();

        let server_res = read_msg(&mut tls_stream).unwrap();
        let credential_res =
            CredentialResponse::<OpaqueCipherSuite>::deserialize(&server_res).unwrap();

        use opaque_ke::errors::ProtocolError::InvalidLoginError;
        let client_login_fin_res = match client_login_start_res.state.finish(
            password.as_bytes(),
            credential_res,
            ClientLoginFinishParameters::default(),
        ) {
            Ok(fin_res) => fin_res,
            Err(InvalidLoginError) => {
                println!("Login failed: wrong username/password.");
                send_msg(&mut self.tcp_socket, b"").unwrap();
                return;
            }
            Err(err) => {
                panic!("{:#?}", err);
            }
        };

        send_msg(
            &mut self.tcp_socket,
            client_login_fin_res.message.serialize().as_slice(),
        )
        .unwrap();

        use aes_gcm_siv::{
            aead::{Aead, KeyInit},
            Aes256GcmSiv, Nonce,
        };

        let key = &client_login_fin_res.session_key.as_slice()[0..32];
        let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
        // Nonce is 96-bits (12 bytes) long
        let mut nonce = Nonce::from_slice(&[0; 12]).to_owned();

        println!("Connected to server.");

        loop {
            let mut msg = String::new();
            io::stdin().read_line(&mut msg).unwrap();
            let msg = msg.trim();

            let ciphertext = cipher.encrypt(&nonce, msg.as_bytes()).unwrap();
            increment_nonce(&mut nonce);

            send_msg(&mut self.tcp_socket, &ciphertext).unwrap();

            if msg == "quit" {
                break;
            }

            let ciphertext = read_msg(&mut self.tcp_socket).unwrap();
            let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
            increment_nonce(&mut nonce);

            let plaintext = String::from_utf8(plaintext).unwrap();
            println!("From server: {plaintext}");
        }
    }

    fn exit(&mut self) {
        self.tcp_socket
            .write_all(&[ClientQuery::Disconnect as u8])
            .unwrap();
    }
}

enum MainMenuChoice {
    Register,
    Login,
    Exit,
    None,
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
        3 => MainMenuChoice::Exit,
        _ => MainMenuChoice::None,
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
            MainMenuChoice::None => (),
        }
    }
}
