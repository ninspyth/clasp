use sha2::{Sha256, Digest};
use rand::{distr, prelude::*};
use digest::Output;

pub fn gen_salt(size: u64) -> String {
    let mut salt: String = String::new();
    let mut rng = rand::rng(); 

    for _ in 0..=size {
        salt.push(rng.sample(distr::Alphanumeric) as char);
    }
    salt
}

pub fn hash_password(pass: &str, salt: &str) -> Output<Sha256>{
    let mut hasher = Sha256::new();
    hasher.update(pass);
    hasher.update(salt);
    hasher.finalize()
}
