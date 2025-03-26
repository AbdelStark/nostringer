import { sign, verify } from "../../src/index.js";
import { ProjectivePoint, utils } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";
import { expect, test, describe } from "@jest/globals";

// Helper to generate valid keypair for testing
function generateKeyPair() {
  const privateKey = utils.randomPrivateKey();
  const privateKeyHex = bytesToHex(privateKey);
  const pubKey = ProjectivePoint.fromPrivateKey(privateKey);
  const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");
  return { privateKeyHex, publicKeyHex };
}

describe("Nostringer Unit Tests", () => {
  test("sign() throws with invalid public key format", () => {
    const msg = "Test Message";
    const keyPair = generateKeyPair();
    // Add a keypair to make the ring size valid, but keep the invalid format
    const ring = ["invalid-public-key", keyPair.publicKeyHex];

    expect(() => sign(msg, keyPair.privateKeyHex, ring)).toThrow(
      /Invalid public key format/,
    );
  });

  test("sign() throws if ring is too small", () => {
    const msg = "Test Message";
    const keyPair = generateKeyPair();
    // Create a ring with only one member (too small)
    const ring = [keyPair.publicKeyHex];

    expect(() => sign(msg, keyPair.privateKeyHex, ring)).toThrow(
      /at least 2 participants/,
    );
  });

  test("sign() throws if ring does not include signer", () => {
    const msg = "Test Message";
    // Create two distinct keypairs
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();
    const keyPair3 = generateKeyPair();
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
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();
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
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();

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
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();

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
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    const msg = 123; // Invalid message type

    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(false);
  });
});
