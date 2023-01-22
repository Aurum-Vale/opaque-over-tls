use std::{
    io::{Read, Write},
    net::TcpStream,
};

fn main() {
    let server_ip = "127.0.0.1:7878";
    let mut stream = TcpStream::connect(server_ip).unwrap();

    let req = "\r\n\r\n";
    stream.write_all(req.as_bytes()).unwrap();

    let mut res = String::new();
    stream.read_to_string(&mut res).unwrap();

    println!("{res}");
}
