# JoyID Lock

## Lock Script Data Structure

```yml
code_hash: joyid_contract_type_id
hash_type: type
args: <2 byte algorithm index><20 byte public key hash>
```

### JoyID Lock args

| algorithm index | algorithm description               | public key hash                                      |
| --------------- | ----------------------------------- | ---------------------------------------------------- |
| 0x0001          | Secp256r1 for WebAuthn              | `blake2b(64bytes_uncompressed_public_key)[0..20]`    |
| 0x0002          | Secp256k1 for Ethereum PersonalSign | `keccak256(64bytes_uncompressed_public_key)[12..32]` |

## Transaction Data Structure

```yml
Input:
	capacity
	lock: joyid-lock

Output:
	capacity
	lock: any lock

Witnesses:
	witness_args.lock = unlock_mode | public_key(_hash, only for secp256k1) | signature | web_authn_msg
  witness_args.output_type = SubKeyUnlockEntries
```

### Unlock Mode

Depending on the value of the `unlock_mode`, the auth content has the following interpretations:

| unlock mode | mode description | Affected WitnessArgs.OutputType      |
| ----------- | ---------------- | ------------------------------------ |
| 0x01        | Native unlock    | Empty                                |
| 0x02        | Subkey unlock    | SubKeyUnlockEntries serialized bytes |

```yml
table SubKeyUnlockEntries {
  ext_data: Uint32,    # the unique index of subkey
  alg_index: Uint16,   # 0x0001 => secp256r1-webAuthn, 0x0002 => secp256k1-eth
  subkey_proof: Bytes, # the SMT proof of subkey
}
```

> The sub public key must be added to [SMT(Sparse Merkle Tree)](https://github.com/nervosnetwork/sparse-merkle-tree) before using subkey to unlock transaction

### WitnessArgs.Lock

- public_key(\_hash, only for secp256k1)

  - 64 byte secp256r1 uncompressed public key
  - 20 byte keccak256 secp256k1 uncompressed public key hash (`keccak256(64bytes_uncompressed_public_key)[12..32]`)

- signature: 64 byte secp256r1 signature for transaction or 65 byte secp256k1 signature for transaction

- web_authn_msg(only for secp256r1): The WebAuthn message which includes [authData](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) and [clientData](https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization).

  - The clientData includes webAuthn challenge(`base64_encode(sighash_all)`)
