use std::{fmt, path::Path, sync::Arc};

use c_kzg::KzgSettings;
use ethers::{
    core::k256::sha2::{Digest, Sha256},
    types::U256,
    utils::keccak256,
};
use once_cell::sync::Lazy;

const MAX_BLOB_TX_PAYLOAD_SIZE: usize = 131072; // 131072 = 4096 * 32 = 1024 * 4 * 32 = 128kb

#[derive(Debug, Clone)]
pub struct Blob(pub [u8; MAX_BLOB_TX_PAYLOAD_SIZE]);


impl Blob {
    pub fn decode_raw_tx_payload(&self) -> Result<Vec<u8>, BlobError> {
        let mut data = vec![0u8; MAX_BLOB_TX_PAYLOAD_SIZE];
        for i in 0..4096 {
            if self.0[i * 32] != 0 {
                return Err(BlobError::InvalidBlob {
                    high_order_byte: self.0[i * 32],
                    field_element: i,
                });
            }

            data[i * 31..i * 31 + 31].copy_from_slice(&self.0[i * 32 + 1..i * 32 + 32]);
        }

        let mut offset: usize = 0;
        let mut chunk_index: u16 = 0;
        let mut payload = Vec::new();
        while offset < MAX_BLOB_TX_PAYLOAD_SIZE {
            let data_len =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            if data_len == 0 {
                break;
            }
            let remaining_len = MAX_BLOB_TX_PAYLOAD_SIZE - offset - 4;
            if data_len > remaining_len {
                return Err(BlobError::DecodeError {
                    chunk_index,
                    data_len,
                    remaining_len,
                });
            }
            payload.extend_from_slice(&data[offset + 4..offset + 4 + data_len]);

            let ret = (4 + data_len) / 31;
            let remainder = (4 + data_len) % 31;
            offset += if remainder > 0 { ret + 1 } else { ret } * 31;
            chunk_index += 1;
        }
        log::info!("blob chunk_index = {:?}", chunk_index);
        Ok(payload)
    }
}

#[derive(Debug)]
pub enum BlobError {
    InvalidBlob {
        high_order_byte: u8,
        field_element: usize,
    },
    DecodeError {
        chunk_index: u16,
        data_len: usize,
        remaining_len: usize,
    },
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BlobError::InvalidBlob {
                high_order_byte,
                field_element,
            } => write!(
                f,
                "Invalid blob, found non-zero high order byte {:x} of field element {}",
                high_order_byte, field_element
            ),
            BlobError::DecodeError {
                chunk_index,
                data_len,
                remaining_len,
            } => write!(
                f,
                "Decode error: dataLen is bigger than remainingLen. chunkIndex: {}, dataLen: {}, remainingLen: {}",
                chunk_index, data_len, remaining_len
            ),
        }
    }
}

impl std::error::Error for BlobError {}

#[test]
fn test_decode_raw_tx_payload_success() {
    let mut raw_data = [0u8; MAX_BLOB_TX_PAYLOAD_SIZE];
    // Construct an effective Blob data
    let payload =
        br#"EIP-4844 introduces a new kind of transaction type to Ethereum which accepts "blobs"
        of data to be persisted in the beacon node for a short period of time. These changes are
        forwards compatible with Ethereum's scaling roadmap, and blobs are small enough to keep disk use manageable."#;

    let mut offset = 0;
    for chunk in payload.chunks(27) {
        let chunk_len = chunk.len() as u32;
        raw_data[offset + 1..offset + 5].copy_from_slice(&chunk_len.to_le_bytes());
        raw_data[offset + 5..offset + 5 + chunk_len as usize].copy_from_slice(chunk);
        offset += 5 + chunk_len as usize;
    }
    let blob = Blob(raw_data);

    // Test the decoderaw_tx_payload method
    let result = blob.decode_raw_tx_payload();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), payload);
}

#[test]
fn test_decode() {
    use bls12_381::Scalar as Fp;

    let data = b"aasgafds5hdfhdfgg";
    // U256::from_little_endian
    let mut challenge_point = keccak256(data);
    println!("{:?}", challenge_point);
    println!("{:?}", U256::from_little_endian(&challenge_point));

    challenge_point[0] = 0;
    let challenge_point_hash = U256::from(&challenge_point);

    println!("to_le_bytes {:?}", challenge_point_hash.to_le_bytes());
    println!("to_be_bytes {:?}", challenge_point_hash.to_be_bytes());
    println!(
        "{:?}",
        U256::from(challenge_point_hash.to_le_bytes()).to_le_bytes()
    );

    println!(
        "a {:?}",
        Fp::from_bytes(&challenge_point_hash.to_le_bytes()).unwrap()
    );
    println!(
        "b {:?}",
        Fp::from_bytes(
            &U256::from_little_endian(
                &Fp::from_bytes(&challenge_point_hash.to_le_bytes())
                    .unwrap()
                    .to_bytes()
            )
            .to_le_bytes()
        )
        .unwrap()
    );
}

pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

/// 4844 trusted setup config
pub static MAINNET_KZG_TRUSTED_SETUP: Lazy<Arc<KzgSettings>> =
    Lazy::new(|| Arc::new(load_trusted_setup()));

/// Loads the trusted setup parameters from the given bytes and returns the [KzgSettings].
pub fn load_trusted_setup() -> KzgSettings {
    let trusted_setup_file = Path::new("./configs/4844_trusted_setup.txt");
    assert!(trusted_setup_file.exists());
    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();
    return kzg_settings;
}

pub fn kzg_to_versioned_hash(commitment: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(commitment);
    let hash = hasher.finalize();
    let mut hashed_bytes = hash.as_slice().to_vec();
    hashed_bytes[0] = 0x01;
    hashed_bytes
}

#[test]
fn test_vec() {
    let mut batch_blob = [0u8; 100];
    batch_blob[0] = 0x1;
    println!("{:?}", batch_blob[99])
}

#[test]
fn test_kzg() {
    use c_kzg::{Blob, KzgCommitment};

    let mut raw_data = [0u8; 131072];
    // Construct an effective Blob data
    let payload = br#"aaaabbbcsdgsgshghkgkhbsfvsbskjgskjdghs232vf"#;

    let mut offset = 0;
    for chunk in payload.chunks(27) {
        let chunk_len = chunk.len() as u32;
        raw_data[offset + 1..offset + 5].copy_from_slice(&chunk_len.to_le_bytes());
        raw_data[offset + 5..offset + 5 + chunk_len as usize].copy_from_slice(chunk);
        offset += 5 + chunk_len as usize;
    }

    let data_hash = kzg_to_versioned_hash(&raw_data);
    println!("data_hash= {:#?}", ethers::utils::hex::encode(&data_hash));

    let kzg_settings: Arc<c_kzg::KzgSettings> = Arc::clone(&MAINNET_KZG_TRUSTED_SETUP);
    let commitment = match KzgCommitment::blob_to_kzg_commitment(
        &Blob::from_bytes(&raw_data).unwrap(),
        &kzg_settings,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("generate KzgCommitment error: {:#?}", e);
            return;
        }
    };

    let versioned_hash = kzg_to_versioned_hash(commitment.to_bytes().to_vec().as_slice());
    println!(
        "versioned_hash_Hex= {:#?}",
        ethers::utils::hex::encode(&versioned_hash)
    );
}

#[test]
fn test_point() {
    let data = [
        255, 94, 167, 190, 153, 44, 233, 37, 194, 184, 37, 4, 5, 135, 251, 15, 139, 43, 6, 128,
        156, 135, 37, 149, 237, 234, 94, 154, 235, 134, 252, 7,
    ];

    println!("point_x= {:#?}", ethers::utils::hex::encode(data));
}
