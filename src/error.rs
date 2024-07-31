#[derive(Debug)]
pub enum RnsError {
    InvalidArgument,
    IncorrectSignature,
    CryptoError,
}
