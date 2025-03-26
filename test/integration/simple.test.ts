import { sign, verify } from "../../src/index";
import { expect, test, describe } from "@jest/globals";
import { generateDeterministicKeyPair } from "../helpers";

describe("Simple Sign/Verify Tests", () => {
  test("Basic sign and verify with 2-member ring", () => {
    // Create deterministic keypairs for reproducible tests
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    // Create a ring with these public keys
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    // Message to sign
    const message = "Simple test message";

    // Sign with first keypair
    const signature = sign(message, keyPair1.privateKeyHex, ring);

    // Verify the signature
    const isValid = verify(signature, message, ring);

    // Should be valid
    expect(isValid).toBe(true);
  });

  test("Multiple signatures produce different results", () => {
    // Create deterministic keypairs
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    // Create a ring
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    const message = "Test unlinkability";

    // Sign multiple times with the same key
    const signature1 = sign(message, keyPair1.privateKeyHex, ring);
    const signature2 = sign(message, keyPair1.privateKeyHex, ring);

    // Both should be valid
    expect(verify(signature1, message, ring)).toBe(true);
    expect(verify(signature2, message, ring)).toBe(true);

    // But they should be different (unlinkability)
    expect(signature1.c0).not.toBe(signature2.c0);
  });
});
