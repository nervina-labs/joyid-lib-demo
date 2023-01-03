use crate::error::Error;
use ckb_lib_joyid::LibCKBJoyID;
use ckb_std::ckb_types::{bytes::Bytes, prelude::*};
use ckb_std::dynamic_loading_c_impl::CKBDLContext;
use ckb_std::high_level::load_script;

const LOCK_ARGS_LEN: usize = 22;
pub fn main() -> Result<(), Error> {
    let mut context = unsafe { CKBDLContext::<[u8; 1280 * 1024]>::new() };
    let lib_joyid = LibCKBJoyID::load(&mut context);

    let joyid_args = load_joyid_data()?;

    lib_joyid
        .verify_joyid_data(&joyid_args)
        .map_err(|err_code| Error::from(err_code))
}

fn load_joyid_data() -> Result<[u8; 22], Error> {
    let args: Bytes = load_script()?.args().unpack();
    if args.len() != LOCK_ARGS_LEN {
        return Err(Error::LockArgsInvalid);
    }
    let mut joyid_args = [0u8; 22];
    joyid_args.copy_from_slice(&args);
    Ok(joyid_args)
}
