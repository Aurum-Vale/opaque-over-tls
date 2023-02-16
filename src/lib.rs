use argon2::Argon2;

pub struct OpaqueCipherSuite;
impl opaque_ke::CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

pub fn send_msg(stream: &mut dyn std::io::Write, data: &[u8]) {
    let data_count: i32 = data.len().try_into().unwrap();
    let data_count_bytes = data_count.to_ne_bytes();
    stream
        .write_all(&[&data_count_bytes[..], data].concat())
        .unwrap();
}

pub fn read_msg(stream: &mut dyn std::io::Read) -> Vec<u8> {
    let mut length_as_bytes: [u8; 4] = [0; 4];
    stream.read_exact(&mut length_as_bytes).unwrap();
    let length = i32::from_ne_bytes(length_as_bytes);

    let mut data = vec![0; length.try_into().unwrap()];
    stream.read_exact(&mut data).unwrap();
    return data;
}
