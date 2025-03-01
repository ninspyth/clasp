use sha2::Digest;

pub fn hash_password<D: Digest>(pass: &str, salt: &str, output: &mut String) {
    !todo();
}

pub fn gen_salt(size: u64) -> String {
    !todo();
}
