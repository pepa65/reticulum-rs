use crypt::fernet::Fernet;
use rand_core::OsRng;

mod crypt;
mod error;

pub fn add() {
    let fernet = Fernet::new_rand(OsRng);
}
