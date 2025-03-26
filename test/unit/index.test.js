import { sign, verify } from "../../src/index.js";
import { ProjectivePoint } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";
import { expect, test, describe } from "@jest/globals";

// Helper function to generate a deterministic keypair with a known seed
function generateDeterministicKeyPair(seed = 1) {
  // Create a deterministic private key from the seed
  const seedBytes = new Uint8Array(32).fill(0);
  seedBytes[31] = seed;
  const privateKeyHex = bytesToHex(seedBytes);

  // Get the public key
  const pubKey = ProjectivePoint.fromPrivateKey(seedBytes);
  const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");

  return { privateKeyHex, publicKeyHex };
}

describe("Nostringer Unit Tests", () => {
  test("sign() throws with invalid public key format", () => {
    const msg = "Test Message";
    const keyPair = generateDeterministicKeyPair(1);
    // Add a keypair to make the ring size valid, but keep the invalid format
    const ring = ["invalid-public-key", keyPair.publicKeyHex];

    expect(() => sign(msg, keyPair.privateKeyHex, ring)).toThrow(
      /Invalid hex string/,
    );
  });

  test("sign() throws if ring is too small", () => {
    const msg = "Test Message";
    const keyPair = generateDeterministicKeyPair(1);
    // Create a ring with only one member (too small)
    const ring = [keyPair.publicKeyHex];

    expect(() => sign(msg, keyPair.privateKeyHex, ring)).toThrow(
      /at least 2 participants/,
    );
  });

  test("sign() throws if ring does not include signer", () => {
    const msg = "Test Message";
    // Create two distinct keypairs
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);
    const keyPair3 = generateDeterministicKeyPair(3);
    // Create a valid ring but without the first keypair
    const ring = [keyPair2.publicKeyHex, keyPair3.publicKeyHex];

    // Try to sign with the first keypair not in the ring
    expect(() => sign(msg, keyPair1.privateKeyHex, ring)).toThrow(
      /must include the signer/,
    );
  });

  test("sign() throws with invalid private key format", () => {
    const msg = "Test Message";
    const sk = "invalid-key"; // Invalid format
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    expect(() => sign(msg, sk, ring)).toThrow(
      /Private key must be 32-byte hex/,
    );
  });

  test("verify() returns false for mismatched ring size", () => {
    const signature = {
      c0: "0000aabbccddeeff0000000000000000000000000000000000000000000000000000000000000000",
      s: ["abc0000000000000000000000000000000000000000000000000000000000000"],
    };

    // Generate valid public keys for testing
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    const msg = "Hello world";

    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(false);
  });

  test("verify() returns false with invalid signature format", () => {
    const signature = {
      c0: "not-hex",
      s: ["not-hex"],
    };

    // Generate valid public keys for testing
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    const msg = "Hello world";

    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(false);
  });

  test("verify() returns false with invalid message type", () => {
    const signature = {
      c0: "0000aabbccddeeff0000000000000000000000000000000000000000000000000000000000000000",
      s: [
        "abc0000000000000000000000000000000000000000000000000000000000000",
        "def0000000000000000000000000000000000000000000000000000000000000",
      ],
    };

    // Generate valid public keys for testing
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    const msg = 123; // Invalid message type

    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(false);
  });
});
