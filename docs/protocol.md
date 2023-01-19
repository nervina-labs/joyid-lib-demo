# JoyID Lock

## Data Structure

### Lock Data Structure

```yml
code_hash: joyid_contract_type_id
hash_type: type
args: <2 byte algorithm index><20 byte main public key hash>
```

| algorithm index | algorithm description               | public key hash                                           |
| --------------- | ----------------------------------- | --------------------------------------------------------- |
| 0x0001          | Secp256r1 for WebAuthn              | `blake2bBytes(64bytes_uncompressed_public_key)[0..20]`    |
| 0x0002          | Secp256k1 for Ethereum PersonalSign | `keccak256Bytes(64bytes_uncompressed_public_key)[12..32]` |

### Transaction Data Structure

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

## Native Mode Unlock

### 1. Build Lock Args

- Secp256r1-WebAuthn

```JavaScript
// secp256r1UncompressedPublicKey: 64 byte
const lockArgs = `0x0001${blake2b(secp256r1UncompressedPublicKey).hex().slice(0, 40)}`
```

- Secp256k1-eth

```JavaScript
// secp256k1UncompressedPublicKey: 64 byte
const lockArgs = `0x0002${keccak256(secp256k1UncompressedPublicKey).hex().slice(24)}`
```

### 2. Calculate the message digest of the transaction

- Secp256r1-WebAuthn

```JavaScript
const emptyFirstWitnessArgs = {
  ...witnesses[0],
  lock: `0x${'0'.repeat(129*2)}`,
}

const serializedEmptyWitnessBytes = hexToBytes(serializeWitnessArgs(emptyFirstWitnessArgs))
const serializedEmptyWitnessSize = serializedEmptyWitnessBytes.length

const hasher = blake2b(32, "ckb-default-hash")
hasher.update(hexToBytes(transactionHash))
hasher.update(hexToBytes(toUint64LittleEndian(`0x${serializedEmptyWitnessSize.toString(16)}`)))
hasher.update(serializedEmptyWitnessBytes)

witnessGroup.slice(1).forEach(w => {
  const bytes = hexToBytes(typeof w === 'string' ? w : serializeWitnessArgs(w))
  hasher.update(hexToBytes(toUint64LittleEndian(`0x${bytes.length.toString(16)}`)))
  hasher.update(bytes)
})
const message = hasher.digest('hex')

```

- Secp256k1-eth

```JavaScript
const emptyFirstWitnessArgs = {
  ...witnesses[0],
  lock: `0x${'0'.repeat(86*2)}`,
}

const serializedEmptyWitnessBytes = hexToBytes(serializeWitnessArgs(emptyFirstWitnessArgs))
const serializedEmptyWitnessSize = serializedEmptyWitnessBytes.length

const hasher = keccak256()
hasher.update(hexToBytes(transactionHash))
hasher.update(hexToBytes(toUint64LittleEndian(`0x${serializedEmptyWitnessSize.toString(16)}`)))
hasher.update(serializedEmptyWitnessBytes)

witnesses.slice(1).forEach(w => {
  const bytes = hexToBytes(typeof w === 'string' ? w : serializeWitnessArgs(w))
  hasher.update(hexToBytes(toUint64LittleEndian(`0x${bytes.length.toString(16)}`)))
  hasher.update(bytes)
})

const message = hasher.hex()
```

### 3. Sign the transaction

- Secp256r1-WebAuthn

```JavaScript
const challenge = base64Encode(message)
const webAuthnClientData = generateClientDataWithChallenge(challenge)
const clientDataHash = sha256Hash(webAuthnClientData)

const authenticatorData = "..."
const signMessage = authenticatorData + clientDataHash

const signature = secp256r1.sign(privateKey, signMessage)
```

> More WebAuthn information can be visited in [AuthenticatorData](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) and [ClientData](https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization)

- Secp256k1-eth

```JavaScript
// Calculate ethereum personalSign hash
const signMessage = ethers.utils.HashMessage(message)
const signature = secp256k1.sign(privateKey, signMessage)
```

### 4. Build WitnessArgs

- Secp256r1-WebAuthn

```JavaScript
const firstGroupWitnessArgs = {
  ...witnesses[0],
  lock: `0x01${mainSecp256r1UncompressedPublicKey}${signature}${authenticatorData}${webAuthnClientData}`,
}
```

- Secp256k1-eth

```JavaScript

const secp256k1PublicKeyHash = keccak256(secp256k1UncompressedPublicKey).hex().slice(24)
const firstGroupWitnessArgs = {
  ...witnesses[0],
  lock: `0x01${mainSecp256k1PublicKeyHash}${signature}`,
}
```

## Subkey Mode Unlock

The signing process of subkey mode is similar to native mode, the difference is that sub private key is used instead of main private key
and the sub public key must be added into CoTA SMT.

Before adding subkey to JoyID account, the CoTA cell should be registered and the [registry example](https://github.com/nervina-labs/cota-sdk-js/blob/develop/example/registry.ts) may be helpful.

> The community cota aggregator services may be helpful to develop and they can be seen on here

[Adding subkey JavaScript example](https://github.com/duanyytop/joyid-sdk-js/blob/develop/example/native-subkey.ts) and [adding subkey Golang example](https://github.com/nervina-labs/joyid-sdk-go/blob/master/example/main.go#L260) can be visited for reference.

The WitnessArgs of subkey mode is different from native mode and the WitnessArgs is constructed as follows:

- Secp256r1-WebAuthn

```JavaScript
const aggregatorRpcRequest = {
  lockScript: serializedJoyIDLockScript,
  pubkeyHash: blake2b(subPublicKey).hex().slice(0, 40),
  algIndex: 0x01,
}
/**
* table SubKeyUnlockEntries {
*  ext_data: Uint32,    # the unique index of subkey
*  alg_index: Uint16,   # 0x0001 => secp256r1-webAuthn, 0x0002 => secp256k1-eth
*  subkey_proof: Bytes, # the SMT proof of subkey
* }
**/
const { unlockEntry } = await aggregator.rpc.generateSubkeyUnlockSmt(aggregatorRpcRequest)
const firstGroupWitnessArgs = {
  ...witnesses[0],
  lock: `0x02${subSecp256r1UncompressedPublicKey}${signature}${authenticatorData}${webAuthnClientData}`,
  outputType: unlockEntry,
}
```

- Secp256k1-eth

```JavaScript
const aggregatorRpcRequest = {
  lockScript: serializedJoyIDLockScript,
  pubkeyHash: keccak256(subPublicKey).hex().slice(0, 40),
  algIndex: 0x02,
}
/**
* table SubKeyUnlockEntries {
*  ext_data: Uint32,    # the unique index of subkey
*  alg_index: Uint16,   # 0x0001 => secp256r1-webAuthn, 0x0002 => secp256k1-eth
*  subkey_proof: Bytes, # the SMT proof of subkey
* }
**/
const { unlockEntry } = await aggregator.rpc.generateSubkeyUnlockSmt(aggregatorRpcRequest)
const firstGroupWitnessArgs = {
  ...witnesses[0],
  lock: `0x02${subSecp256r1UncompressedPublicKey}${signature}`,
  outputType: unlockEntry,
}
```
