<div align="center">

<a href="https://github.com/AbdelStark/nostringer/actions/workflows/ci.yml"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/AbdelStark/nostringer/ci.yml?style=for-the-badge" height=30></a>
<a href="https://bitcoin.org/"> <img alt="Bitcoin" src="https://img.shields.io/badge/Bitcoin-000?style=for-the-badge&logo=bitcoin&logoColor=white" height=30></a>
<a href="https://github.com/nostr-protocol/nostr"> <img alt="Nostr" src="https://img.shields.io/badge/Nostr-000?style=for-the-badge" height=30></a>

</div>

# Nostringer

An easy-to-use JavaScript library providing **unlinkable ring signatures** (SAG) for Nostr pubkeys. It allows a signer to prove membership in a group of Nostr accounts without revealing which specific account produced the signature.

Nostringer is largely inspired by [Monero's Ring Signatures](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf) using Spontaneous Anonymous Group signatures (SAG), and [beritani/ring-signatures](https://github.com/beritani/ring-signatures) implementation of ring signatures using the elliptic curve Ed25519 and Keccak for hashing.

## Table of Contents

- [Nostringer](#nostringer)
  - [Table of Contents](#table-of-contents)
  - [Disclaimer](#disclaimer)
  - [Problem Statement](#problem-statement)
  - [Key Features](#key-features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Signing](#signing)
    - [Verification](#verification)
  - [API Reference](#api-reference)
    - [`sign(message, privateKeyHex, publicKeysHex[])`](#signmessage-privatekeyhex-publickeyshex)
    - [`verify(signature, message, publicKeysHex[])`](#verifysignature-message-publickeyshex)
  - [License](#license)
  - [References](#references)

## Disclaimer

> **This code is highly experimental**.
> **I am not a cryptographer** and this library has not been audited or formally verified.  
> Use for educational exploration at your own risk. Production usage is **strongly** discouraged until further review and testing are performed.

## Problem Statement

In many scenarios, you want to prove that "someone among these N credentials produced this signature," but you do **not** want to reveal which credential or identity. For instance, you might have a set of recognized people / entities (Nostr pubkeys) who are allowed to post reviews or do priviledged actions, but you want them to be anonymous within that set.

A **ring signature** solves this problem by letting an **individual** sign a message with a group of possible public keys. A verifier can confirm that the message indeed came from **one** of those public keys, without knowing which.

## Key Features

- **Unlinkable**: Each signature hides the signer's identity. Two signatures from the same signer cannot be linked.
- **Pure JS**: Uses [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) for curve ops and [@noble/hashes/sha3](https://github.com/paulmillr/noble-hashes) for Keccak-256 hashing.
- **BIP-340**: Directly supports Nostr x-only pubkeys (32-byte hex strings).
- **Easy to Use**: Simple `sign` and `verify` functions, minimal config needed.
- **TypeScript-Friendly**: Written in modern ES modules and JSDoc, easy to integrate in TS projects.

## Installation

```bash
# using npm
npm install nostringer

# or using yarn
yarn add nostringer
```

## Usage

```js
import { sign, verify } from "nostringer";

// Example: 3-member ring, with 'signerSK' as the signer's private key in hex
const ringPubKeys = [
  "fa...1", // 32-byte hex: Nostr x-only pubkey #1
  "65...d", // #2
  "a0...9", // #3
];

const message = "Hello from ring signature land!";
const signature = sign(message, signerSK, ringPubKeys);

console.log("Generated signature:", signature);

// On the other side, to verify:
const isValid = verify(signature, message, ringPubKeys);
console.log("Is ring signature valid?", isValid);
```

### Signing

- `sign(message, privateKeyHex, publicKeysArray)`
  - Returns a JSON object containing `c0` (initial challenge) and `s` (array of ring responses).
  - The ring must include the signer's public key, otherwise signing fails.

### Verification

- `verify(signature, message, publicKeysArray)`
  - Returns `true` if the ring signature is valid for exactly that ring (i.e., includes the signer's pubkey) and the message. Otherwise `false`.

## API Reference

### `sign(message, privateKeyHex, publicKeysHex[])`

- **message**: `string | Uint8Array` – The data you wish to sign.
- **privateKeyHex**: `string` – 64-hex string representing the signer's **32-byte** secp256k1 private key.  
  (e.g., `"e0f9c0...3fb"`).
- **publicKeysHex**: `string[]` – Array of ring members' Nostr x-only public keys (each 32-byte hex).

**Returns**: `RingSignature`

```ts
interface RingSignature {
  c0: string; // initial challenge, 64-hex
  s: string[]; // array of ring responses, 64-hex each
}
```

**Throws**:

- If the signer's pubkey is not in the ring.
- If keys are invalid or incorrectly formatted.

### `verify(signature, message, publicKeysHex[])`

- **signature**: `RingSignature` – The object produced by `sign`.
- **message**: `string | Uint8Array` – The original message.
- **publicKeysHex**: `string[]` – The same ring of pubkeys used by the signer.

**Returns**: `boolean` – `true` if the signature is valid and ring membership is proven, otherwise `false`.

## License

This project is licensed under the [MIT License](License).

## References

- [Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups](https://eprint.iacr.org/2004/027.pdf) - (Joseph Liu et al., 2004) – basis of LSAG.
- [Beritani, ring-signatures JS library](https://github.com/beritani/ring-signatures) – Ed25519 ring signature implementation (SAG, bLSAG, MLSAG, CLSAG)​.
- [Blockstream Elements rust-secp256k1-zkp library](https://github.com/BlockstreamResearch/rust-secp256k1-zkp) – Whitelist Ring Signature in libsecp256k1-zkp (C code exposed via Rust)​.
- [Zero to Monero 2.0 – Chapter 3, ring signature algorithms](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf).
- [Cronokirby Blog – On Monero’s Ring Signatures](https://cronokirby.com/posts/2022/03/on-moneros-ring-signatures), explains Schnorr ring signatures in detail​.

---

Started with love by [AbdelStark](https://github.com/AbdelStark) 🧡

Feel free to follow me on Nostr if you’d like, using my public key:

```text
npub1hr6v96g0phtxwys4x0tm3khawuuykz6s28uzwtj5j0zc7lunu99snw2e29
```

Or just **scan this QR code** to find me:

![Nostr Public Key QR Code](https://hackmd.io/_uploads/SkAvwlYYC.png)
