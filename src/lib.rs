use aes_gcm_siv::aead::{consts::U12, generic_array::GenericArray};
use argon2::Argon2;

/// The algorithm suite used by OPAQUE.
pub struct OpaqueCipherSuite;
impl opaque_ke::CipherSuite for OpaqueCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

#[repr(u8)]
pub enum ClientQuery {
    Registration = 0,
    Login = 1,
    Disconnect = 2,
}

impl TryFrom<u8> for ClientQuery {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientQuery::Registration),
            1 => Ok(ClientQuery::Login),
            2 => Ok(ClientQuery::Disconnect),
            _ => Err(()),
        }
    }
}

/// Send a message over TCP or TLS.
pub fn send_msg(stream: &mut dyn std::io::Write, data: &[u8]) -> Result<(), std::io::Error> {
    let data_count: u64 = data.len() as u64;
    let data_count_bytes = data_count.to_le_bytes();
    stream.write_all(&[&data_count_bytes[..], data].concat())
}

/// Receive a message from a TCP or TLS stream.
pub fn read_msg(stream: &mut dyn std::io::Read) -> Result<Vec<u8>, std::io::Error> {
    let mut length_as_bytes: [u8; 8] = [0; 8];
    stream.read_exact(&mut length_as_bytes)?;
    let length = u64::from_le_bytes(length_as_bytes);

    let mut data = vec![0; length as usize];
    stream.read_exact(&mut data)?;
    Ok(data)
}

pub fn increment_nonce(nonce: &mut GenericArray<u8, U12>) {
    for i in 0..12 {
        // Rust does not like implicit overflows...
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            break;
        }
    }
}
