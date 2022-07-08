use std::path::Path;

mod tests {
    use super::*;
    use keystore::decrypt_key;
    use keystore::new_random_keystore;

    #[test]
    fn test_generate() {
        let dir = Path::new("./tests/keystore");
        let mut rng = rand::thread_rng();

        let (pk, name) = new_random_keystore(dir, &mut rng, "some_password").unwrap_or_else(|e| {
            println!("err: {:?}", e);
            (vec![], String::default())
        });

        println!("{:?}\n{:?}", hex::encode(&pk), name);
    }

    #[test]
    fn test_decrypt() {
        let dir = Path::new("./tests/keystore/77457c14-05c1-4f4d-a410-80389a44a462");
        let pk = decrypt_key(dir, "some_password").unwrap_or_else(|e| {
            println!("err: {:?}", e);
            vec![]
        });
        println!("{:?}", hex::encode(&pk));
        assert_eq!(
            pk,
            hex::decode("fdfab23693d3c3f8905497ab7ac59dbdcd18e24a0dd12c48f2ded10b98c1aba1")
                .unwrap()
        );
    }
}
