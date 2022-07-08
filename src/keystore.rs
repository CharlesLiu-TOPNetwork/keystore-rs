use ethereum_types::H160 as Address;
use hex::{FromHex, ToHex};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use uuid::Uuid;

fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.encode_hex::<String>())
}

fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Keystore {
    pub address: Address,
    pub crypto: CryptoJson,
    pub id: Uuid,
    pub version: u8,
}

/// "crypto" part of keystore json
#[derive(Debug, Deserialize, Serialize)]
pub struct CryptoJson {
    pub cipher: String,

    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub ciphertext: Vec<u8>,

    pub cipherparams: CipherparamsJson,

    pub kdf: KdfType,

    pub kdfparams: KdfparamsType,

    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CipherparamsJson {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KdfType {
    Scrypt,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
/// Defines the various parameters used in the supported KDFs.
pub enum KdfparamsType {
    Scrypt {
        dklen: u8,
        n: u32,
        p: u32,
        r: u32,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
        salt: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_ds_from_json_data() {
        let json_data = r#"
        {
            "address": "96932b7a373d8586c4a2d3c98517803ff2818cec",
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "1f5f3d1d6ac1b6a83420fb871ecd094cd5718e2f91efb149516ec61ebaf5e990",
                "cipherparams": {
                    "iv": "f0186df298a0bcf6b36e88494a8b08d6"
                },
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "f2511606e5b9f3da34c6f3009ec58651dfbfb5e2b93e70b64b412633fa6ce43b"
                },
                "mac": "76f601c7e386a243be9f4a406270890e4591891cbdc33ca1bc9e823b927685d0"
            },
            "id": "b1f40874-2961-4412-ab31-e7b5ec07eafd",
            "version": 3
        }
        "#;
        let keystore: Keystore = serde_json::from_str(json_data).unwrap();
        assert_eq!(
            keystore.address.as_bytes(),
            hex::decode("96932b7a373d8586c4a2d3c98517803ff2818cec")
                .unwrap()
                .as_slice()
        );

        assert_eq!(
            keystore.crypto.cipherparams.iv.as_slice(),
            hex::decode("f0186df298a0bcf6b36e88494a8b08d6")
                .unwrap()
                .as_slice()
        );

        assert_eq!(
            keystore.crypto.kdfparams,
            KdfparamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 1,
                r: 8,
                salt: hex::decode(
                    "f2511606e5b9f3da34c6f3009ec58651dfbfb5e2b93e70b64b412633fa6ce43b"
                )
                .unwrap()
                .to_vec()
            }
        )
    }
}
