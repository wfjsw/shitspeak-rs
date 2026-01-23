
#[derive(Debug)]
pub enum CryptError {
    InvalidNonceSize,
    CipherError(aws_lc_rs::error::Unspecified),
    DataTooShort,
    TagMismatch,
    InvalidKeySize,
}

impl From<aws_lc_rs::error::Unspecified> for CryptError {
    fn from(err: aws_lc_rs::error::Unspecified) -> Self {
        CryptError::CipherError(err)
    }
}

impl std::fmt::Display for CryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptError::InvalidNonceSize => write!(f, "Invalid nonce size"),
            CryptError::CipherError(_) => write!(f, "Cipher error"),
            CryptError::DataTooShort => write!(f, "Data too short"),
            CryptError::TagMismatch => write!(f, "Tag mismatch"),
            CryptError::InvalidKeySize => write!(f, "Invalid key size"),
        }
    }
}

impl std::error::Error for CryptError {}
