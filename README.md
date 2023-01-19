# joyid-lib-demo

A contract demo demonstrate JoyID unlock via dynamic link library joyid.so(ckb-lib-joyid/build/joyid.so)

[JoyID Lock Script Introduction](./docs/protocol.md)

**The contract demo deployment on testnet can be seen in [wiki-testnet-deployment](https://github.com/nervina-labs/joyid-lib-demo/wiki/Testnet-Deployment)**

This project contains two crates:

- ckb-lib-joyid - a library helps users do JoyID unlock via dynamic loading, you can reference it in your own project.
- contracts/ckb-lib-demo - a contract demo with rust language that demonstrate how to use the ckb-lib-joyid library.
- contracts/c - a rust contract demo with c language that demonstrate how to use the joyid.so.

## joyid.so

joyid.so provides `verify_joyid_data` to be called to verify JoyID native and subkey unlock.

```c
__attribute__((visibility("default"))) int verify_joyid_data(
    uint8_t *joyid_args, uint32_t args_len)
```

- `joyid_args: algorithm_index(uint16) + public_key_hash(20bytes)`
- algorithm index:
  - 0x0001 => Secp256r1-WebAuthn
  - 0x0002 => Secp256k1-eth
- public_key_hash:
  - `blake2b_hash(secp256r1_uncompressed_public_key)[0..20]`
  - `keccak256_hash(secp256k1_uncompressed_public_key)[12..32]`
  - the length of uncompressed public key is 64 bytes
- args_len must be 22

## Build and Test

Init submodules:

```sh
git submodule init && git submodule update -r --init
```

Build contracts:

```sh
make build
```

Run tests:

```sh
make test
```
