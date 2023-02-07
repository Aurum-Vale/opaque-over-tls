use std::{
    fs,
    io::{prelude::*, BufReader},
    net::TcpListener,
    sync::Arc,
};

use rustls::ServerConnection;

struct ServerApp {
    tls_conn: ServerConnection,
    tcp_listener: TcpListener,
}

// Static impl
impl ServerApp {
    // TODO Unwrap management
    fn init() -> ServerApp {
        let server_cert = "openssl/server.crt";
        let server_priv_key = "openssl/server.key";
        let server_ip = "127.0.0.1:7878";

        let certs = Self::load_certs(server_cert);
        let private_key = Self::load_private_key(server_priv_key);

        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .expect("bad certificates/private key"),
        );

        let tls_conn = ServerConnection::new(config).unwrap();

        let tcp_listener = TcpListener::bind(server_ip).unwrap();

        ServerApp {
            tls_conn,
            tcp_listener,
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
        let mut tcp_socket = self.tcp_listener.accept().unwrap().0;
        let mut stream = rustls::Stream::new(&mut self.tls_conn, &mut tcp_socket);

        let mut buf: [u8; 32] = [0; 32];
        let r = stream.read(&mut buf).unwrap();

        println!("Read {r}");
        println!("{:#?}", String::from_utf8_lossy(&buf[..r]));

        stream.write_all(&buf[..r]).unwrap();
    }
}

fn main() {
    let mut app = ServerApp::init();
    app.accept_connection()
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
