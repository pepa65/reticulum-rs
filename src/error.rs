#[derive(Debug)]
pub enum RnsError {
    InvalidArgument,
    IncorrectSignature,
    IncorrectHash,
    CryptoError,
}
