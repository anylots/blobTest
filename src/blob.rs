use std::fmt;

const MAX_BLOB_TX_PAYLOAD_SIZE: usize = 131072; // Adjust this value as needed

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
