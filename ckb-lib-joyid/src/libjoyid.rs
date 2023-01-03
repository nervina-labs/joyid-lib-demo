use crate::code_hashes::CODE_HASH_JOYID;
use ckb_std::dynamic_loading_c_impl::{CKBDLContext, Symbol};

const VERIFY_JOYID_DATA: &[u8; 17] = b"verify_joyid_data";
type VerifyJoyidData = unsafe extern "C" fn(joyid_args: *const u8, args_len: u32) -> i32;

pub struct LibCKBJoyID {
    verify_joyid_data: Symbol<VerifyJoyidData>,
}

impl LibCKBJoyID {
    pub fn load<T>(context: &mut CKBDLContext<T>) -> Self {
        // load library
        let lib = context.load(&CODE_HASH_JOYID).expect("load joyid");

        // find symbols
        let verify_joyid_data = unsafe {
            lib.get(VERIFY_JOYID_DATA)
                .expect("load verify joyid function")
        };
        LibCKBJoyID { verify_joyid_data }
    }

    pub fn verify_joyid_data(&self, joyid_args: &[u8]) -> Result<(), i32> {
        let verify_joyid_data_f = &self.verify_joyid_data;
        let args_len = joyid_args.len() as u32;
        let error_code = unsafe { verify_joyid_data_f(joyid_args.as_ptr(), args_len) };
        if error_code != 0 {
            return Err(error_code);
        }
        Ok(())
    }
}
