use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    LockArgsInvalid = 5,
    WitnessLengthError,
    WitnessModeError,
    WitnessArgsParseError,
    Secp256r1SigVerifyError,
    Secp256k1SigVerifyError = 10,
    ClientWithoutChallenge,
    AlgorithmIndexError,
    CellDepCotaCellError,
    SMTProofVerifyFailed,
    CoTADataInvalid = 15,

    LibInternalError = 127,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

impl From<i32> for Error {
    fn from(err: i32) -> Self {
        match err {
            5 => Error::LockArgsInvalid,
            6 => Error::WitnessLengthError,
            7 => Error::WitnessModeError,
            8 => Error::WitnessArgsParseError,
            9 => Error::Secp256r1SigVerifyError,
            10 => Error::Secp256k1SigVerifyError,
            11 => Error::ClientWithoutChallenge,
            12 => Error::AlgorithmIndexError,
            13 => Error::CellDepCotaCellError,
            14 => Error::SMTProofVerifyFailed,
            15 => Error::CoTADataInvalid,
            _ => Error::LibInternalError,
        }
    }
}
