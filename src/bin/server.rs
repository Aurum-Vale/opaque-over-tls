use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    sync::Arc,
};

use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration,
};
use opaque_over_tls::{increment_nonce, read_msg, send_msg, ClientQuery, OpaqueCipherSuite};
use rand::rngs::OsRng;
use rustls::{ServerConfig, ServerConnection};

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

        let certs = Self::load_certs(server_cert).expect("Should load server certificate");
        let private_key =
            Self::load_private_key(server_priv_key).expect("Should load server private key");

        Arc::new(
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .expect("Bad certificates or private key"),
        )
    }

    fn init_listener() -> TcpListener {
        let server_ip = "127.0.0.1:7878";
        TcpListener::bind(server_ip).expect("Should open listening TCP port")
    }

    fn init_opaque() -> opaque_ke::ServerSetup<
        OpaqueCipherSuite,
        opaque_ke::keypair::PrivateKey<opaque_ke::Ristretto255>,
    > {
        use std::path::Path;

        if Path::new("credentials/server.setup").is_file() {
            let setup_data = fs::read(Path::new("credentials/server.setup")).unwrap();

            opaque_ke::ServerSetup::<
                OpaqueCipherSuite,
                opaque_ke::keypair::PrivateKey<opaque_ke::Ristretto255>,
            >::deserialize(&setup_data)
            .expect("OPAQUE server setup file should be deserializable")
        } else {
            println!("Missing OPAQUE server setup. Regenerating.");

            fs::remove_dir_all(Path::new("credentials")).unwrap_or(());
            fs::create_dir("credentials")
                .expect("Should be able to create credentials sub-directory");

            let mut rng = OsRng;
            let setup = opaque_ke::ServerSetup::<
                OpaqueCipherSuite,
                opaque_ke::keypair::PrivateKey<opaque_ke::Ristretto255>,
            >::new(&mut rng);

            let setup_data = setup.serialize();
            let mut file = std::fs::File::create("credentials/server.setup").unwrap();
            file.write_all(&setup_data).unwrap();

            setup
        }
    }

    fn init_credentials() -> HashMap<String, ServerRegistration<OpaqueCipherSuite>> {
        use std::path::Path;
        let mut cred_map = HashMap::new();

        let dir_it = fs::read_dir(Path::new("credentials"))
            .expect("Credentials sub-folder should exist and be readable");

        for entry in dir_it {
            let entry_path = entry
                .expect("All entries in the credential subdir should be readable")
                .path();
            if entry_path.extension().unwrap_or(&OsString::from("")) == "bin" {
                let name_path = entry_path.with_extension("name");
                let username = String::from_utf8(
                    fs::read(name_path).expect("Credentials files should be readable"),
                )
                .expect("Username should be valid UTF-8");

                let bin_data = fs::read(entry_path).expect("Credentials files should be readable");
                let creds = ServerRegistration::<OpaqueCipherSuite>::deserialize(&bin_data)
                    .expect("Credentials files should be deserializable");

                cred_map.insert(username, creds);
            }
        }

        cred_map
    }

    fn init() -> ServerApp {
        let tls_config = Self::init_tls();
        let tcp_listener = Self::init_listener();
        let opaque_setup = Self::init_opaque();
        let credentials_map = Self::init_credentials();

        ServerApp {
            tls_config,
            tcp_listener,
            opaque_setup,
            credentials_map,
        }
    }

    fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, std::io::Error> {
        let certfile = fs::File::open(filename)?;
        let mut reader = BufReader::new(certfile);
        let certs = rustls_pemfile::certs(&mut reader)?
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect();

        Ok(certs)
    }

    // TODO better refactor
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
}

// Method impl
impl ServerApp {
    fn accept_connection(&mut self) {
        let mut tls_socket = self.tcp_listener.accept().unwrap().0;

        let mut tls_conn = ServerConnection::new(self.tls_config.clone()).unwrap();

        while tls_conn.is_handshaking() {
            if let Err(_) = tls_conn.complete_io(&mut tls_socket) {
                println!("TLS handshake failed.");
                return;
            }
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

            match buf_choice[0].try_into() {
                Ok(ClientQuery::Registration) => self.register(&mut client),
                Ok(ClientQuery::Login) => self.login(&mut client),
                Ok(ClientQuery::Disconnect) => break,
                Err(_) => break,
            }
        }
    }

    fn register(&mut self, client: &mut Client) {
        let mut tls_stream = rustls::Stream::new(&mut client.tls_conn, &mut client.tls_socket);

        let client_username = String::from_utf8(read_msg(&mut tls_stream).unwrap()).unwrap();
        println!("{client_username}");

        let reg_req = read_msg(&mut tls_stream).unwrap();
        // println!("Read {}", reg_req.len());
        // println!("{:#?}", String::from_utf8_lossy(&reg_req));

        if self.credentials_map.contains_key(&client_username) {
            send_msg(&mut tls_stream, b"").unwrap();
            return;
        }

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
        )
        .unwrap();

        let reg_upload = read_msg(&mut tls_stream).unwrap();
        // println!("Read {}", reg_upload.len());
        // println!("{:#?}", String::from_utf8_lossy(&reg_upload));

        let registration_fin =
            RegistrationUpload::<OpaqueCipherSuite>::deserialize(&reg_upload).unwrap();

        let client_credentials = ServerRegistration::<OpaqueCipherSuite>::finish(registration_fin);

        let cred_bin = client_credentials.serialize();
        let filename = format!("credentials/{}.bin", self.credentials_map.len());
        let mut file = std::fs::File::create(filename).unwrap();
        file.write_all(&cred_bin).unwrap();
        let filename = format!("credentials/{}.name", self.credentials_map.len());
        let mut file = std::fs::File::create(filename).unwrap();
        file.write_all(client_username.as_bytes()).unwrap();

        self.credentials_map
            .insert(client_username, client_credentials);
    }

    // TODO error handling
    fn login(&mut self, client: &mut Client) {
        let mut tls_stream = rustls::Stream::new(&mut client.tls_conn, &mut client.tls_socket);

        let client_username = String::from_utf8(read_msg(&mut tls_stream).unwrap()).unwrap();

        // If the user does not exist, set password file to None
        // ServerLogin::start() will reply with a dummy CredentialResponse
        // This prevents leaking the information of the user not existing.
        let password_file = match self.credentials_map.get(&client_username) {
            Some(pw_file) => Some(pw_file.clone()),
            None => None,
        };

        let login_req = read_msg(&mut tls_stream).unwrap();
        let client_login_req =
            CredentialRequest::<OpaqueCipherSuite>::deserialize(&login_req).unwrap();

        let mut server_rng = OsRng;

        let server_login_start_res = ServerLogin::<OpaqueCipherSuite>::start(
            &mut server_rng,
            &self.opaque_setup,
            password_file.clone(),
            client_login_req,
            client_username.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        send_msg(
            &mut tls_stream,
            server_login_start_res.message.serialize().as_slice(),
        )
        .unwrap();

        let client_res = read_msg(&mut client.tcp_socket).unwrap();

        if client_res.len() == 0 {
            println!("Login aborted by user");
            return;
        }

        let credential_fin =
            CredentialFinalization::<OpaqueCipherSuite>::deserialize(&client_res).unwrap();

        let server_login_fin_res = server_login_start_res.state.finish(credential_fin).unwrap();

        use aes_gcm_siv::{
            aead::{Aead, KeyInit},
            Aes256GcmSiv, Nonce,
        };

        let key = &server_login_fin_res.session_key.as_slice()[0..32];
        let cipher = Aes256GcmSiv::new_from_slice(key).unwrap();
        // Nonce is 96-bits (12 bytes) long
        let mut nonce = Nonce::from_slice(&[0; 12]).to_owned();

        println!("{client_username} is connected.");

        loop {
            let ciphertext = read_msg(&mut client.tcp_socket).unwrap();
            let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
            increment_nonce(&mut nonce);

            let plaintext = String::from_utf8(plaintext).unwrap();
            println!("From client: {plaintext}");

            if plaintext == "quit" {
                break;
            }

            let reply: String = plaintext.chars().rev().collect();
            let ciphertext = cipher.encrypt(&nonce, reply.as_bytes()).unwrap();
            increment_nonce(&mut nonce);

            send_msg(&mut client.tcp_socket, &ciphertext).unwrap();
        }
    }
}

fn main() {
    let mut app = ServerApp::init();
    loop {
        app.accept_connection();
    }
}
