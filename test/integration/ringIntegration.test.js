import { sign, verify } from "../../src/index.js";
import { ProjectivePoint, utils } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";
import { expect, test, describe } from "@jest/globals";

// Helper function to generate test keypairs
function generateKeyPair() {
  const privateKey = utils.randomPrivateKey();
  const privateKeyHex = bytesToHex(privateKey);
  const pubKey = ProjectivePoint.fromPrivateKey(privateKey);
  // X-only pubkey (32-byte hex)
  const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");
  return { privateKeyHex, publicKeyHex };
}

describe("Nostringer Integration Tests", () => {
  // Basic test with fixed known keys for predictable results
  test("Ring signature with fixed keys", () => {
    // Use fixed private key and public keys for deterministic testing
    const privateKeyHex =
      "0000000000000000000000000000000000000000000000000000000000000001";

    // Get corresponding public key
    const privBytes = new Uint8Array(32).fill(0);
    privBytes[31] = 1;
    const pubKey = ProjectivePoint.fromPrivateKey(privBytes);
    const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");

    // Generate a second key for the ring
    const keyPair2 = generateKeyPair();

    // Make ring with two members
    const ring = [publicKeyHex, keyPair2.publicKeyHex];

    // Message to sign
    const message = "Test with fixed keys";

    // Create signature
    const signature = sign(message, privateKeyHex, ring);

    // Log signature for debugging
    console.log("Signature:", signature);
    console.log("Ring:", ring);

    // Verify signature
    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);
  });

  test("Ring signature works for ring of 2 members", () => {
    const msg = "Integration test with 2 members";

    // Generate 2 random keypairs
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();

    // Create a ring of two public keys
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    // Sign with keypair1
    const signature = sign(msg, keyPair1.privateKeyHex, ring);
    expect(signature).toHaveProperty("c0");
    expect(signature.s).toHaveLength(ring.length);

    // Verify the signature with the ring
    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(true);

    // Different message should fail
    const isValidWithWrongMsg = verify(signature, "Wrong message", ring);
    expect(isValidWithWrongMsg).toBe(false);

    // Different ring should fail
    const otherKeyPair = generateKeyPair();
    const alteredRing = [keyPair1.publicKeyHex, otherKeyPair.publicKeyHex];
    const isValidWithAlteredRing = verify(signature, msg, alteredRing);
    expect(isValidWithAlteredRing).toBe(false);
  });

  test("Ring signature works for ring of 3 members", () => {
    const msg = "Integration test with 3 members";

    // Generate 3 random keypairs
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();
    const keyPair3 = generateKeyPair();

    const ring = [
      keyPair1.publicKeyHex,
      keyPair2.publicKeyHex,
      keyPair3.publicKeyHex,
    ];

    // Sign with keypair2
    const signature = sign(msg, keyPair2.privateKeyHex, ring);
    expect(signature).toHaveProperty("c0");
    expect(signature.s).toHaveLength(ring.length);

    // Verification should pass with correct ring
    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(true);

    // Verification should fail if signer is removed from ring
    const ringWithoutSigner = [keyPair1.publicKeyHex, keyPair3.publicKeyHex];
    const isValidWithoutSigner = verify(signature, msg, ringWithoutSigner);
    expect(isValidWithoutSigner).toBe(false);
  });

  test("Ring signature works with Uint8Array message", () => {
    const msgString = "Integration test with binary message";
    const msgBytes = new TextEncoder().encode(msgString);

    // Generate 2 random keypairs
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    // Sign with keypair1 using binary message
    const signature = sign(msgBytes, keyPair1.privateKeyHex, ring);

    // Verify with binary message
    const isValid = verify(signature, msgBytes, ring);
    expect(isValid).toBe(true);

    // Verify with string message - should be valid as the content is the same
    const isValidWithString = verify(signature, msgString, ring);
    expect(isValidWithString).toBe(true);
  });
});
