#include "blockchain.h"
#include "ckb_syscalls.h"
#include "ckb_dlfcn.h"
#include "stdio.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768
#define JOYID_ARGS_SIZE 22

#define EXPORTED_FUNC_NAME "verify_joyid_data"
#define MAX_CODE_SIZE (1024 * 1024)

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_CANT_FIND_SYMBOL -23

typedef unsigned __int128 uint128_t;

// Copied from ${PROJECT_ROOT}/ckb-lib-joyid/src/code_hashes.rs
static const uint8_t JOYID_LIB_CODE_HASH[] = {
    143, 111, 95, 5, 139, 142, 119, 35, 99, 203, 78, 144, 101, 102, 131, 195, 49, 95, 11, 88, 40,
    64, 2, 223, 185, 20, 16, 155, 216, 22, 187, 251,
};

int load_joyid_data(uint8_t* joyid_args) {
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  memcpy(joyid_args, args_bytes_seg.ptr, args_bytes_seg.size);

  return CKB_SUCCESS;
}


typedef int (*ValidateFuncType)(uint8_t* joyid_args, uint32_t args_len);
int verify_joyid_data(uint8_t* joyid_args, uint32_t args_len) {
  uint8_t code_buff[MAX_CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));
  void* handle = NULL;
  size_t consumed_size = 0;
  ValidateFuncType func;

  int ret = ckb_dlopen2(JOYID_LIB_CODE_HASH, 0, code_buff,
                    MAX_CODE_SIZE, &handle, &consumed_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  func = (ValidateFuncType)ckb_dlsym(handle, EXPORTED_FUNC_NAME);
  if (func == NULL) {
    return ERROR_CANT_FIND_SYMBOL;
  }

  ret = func(joyid_args, args_len);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  return CKB_SUCCESS;
}

int main() {
  uint8_t joyid_args[JOYID_ARGS_SIZE];

  int ret = load_joyid_data(joyid_args);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  ret = verify_joyid_data(joyid_args, JOYID_ARGS_SIZE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  return CKB_SUCCESS;
}

