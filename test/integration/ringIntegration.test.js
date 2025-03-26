import { sign, verify } from "../../src/index.js";
import { ProjectivePoint, utils } from "@noble/secp256k1";
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

// Helper function to generate random keypairs for non-critical tests
function generateKeyPair() {
  const privateKey = utils.randomPrivateKey();
  const privateKeyHex = bytesToHex(privateKey);
  const pubKey = ProjectivePoint.fromPrivateKey(privateKey);
  const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");
  return { privateKeyHex, publicKeyHex };
}

describe("Nostringer Integration Tests", () => {
  // Basic test with fixed known keys for predictable results
  test("Ring signature with fixed keys", () => {
    // Use fixed private key (value = 1)
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    // Make ring with two members
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    // Message to sign
    const message = "Test with fixed keys";

    // Create signature using deterministic mode
    const signature = sign(message, keyPair1.privateKeyHex, ring, {
      deterministic: true,
    });

    // Log signature for debugging
    console.log("Signature:", signature);
    console.log("Ring:", ring);

    // Verify signature
    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);
  });

  test("Ring signature works for ring of 2 members", () => {
    const msg = "Integration test with 2 members";

    // Generate 2 deterministic keypairs
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    // Create a ring of two public keys
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    // Sign with keypair1 using deterministic mode
    const signature = sign(msg, keyPair1.privateKeyHex, ring, {
      deterministic: true,
    });
    expect(signature).toHaveProperty("c0");
    expect(signature.s).toHaveLength(ring.length);

    // Verify the signature with the ring
    const isValid = verify(signature, msg, ring);
    expect(isValid).toBe(true);

    // Different message should fail
    const isValidWithWrongMsg = verify(signature, "Wrong message", ring);
    expect(isValidWithWrongMsg).toBe(false);

    // Different ring should fail
    const keyPair3 = generateDeterministicKeyPair(3);
    const alteredRing = [keyPair1.publicKeyHex, keyPair3.publicKeyHex];
    const isValidWithAlteredRing = verify(signature, msg, alteredRing);
    expect(isValidWithAlteredRing).toBe(false);
  });

  test("Ring signature works for ring of 3 members", () => {
    const msg = "Integration test with 3 members";

    // Generate 3 deterministic keypairs
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);
    const keyPair3 = generateDeterministicKeyPair(3);

    const ring = [
      keyPair1.publicKeyHex,
      keyPair2.publicKeyHex,
      keyPair3.publicKeyHex,
    ];

    // Sign with keypair2 using deterministic mode
    const signature = sign(msg, keyPair2.privateKeyHex, ring, {
      deterministic: true,
    });
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

    // Generate 2 deterministic keypairs
    const keyPair1 = generateDeterministicKeyPair(1);
    const keyPair2 = generateDeterministicKeyPair(2);

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];

    // Sign with keypair1 using binary message and deterministic mode
    const signature = sign(msgBytes, keyPair1.privateKeyHex, ring, {
      deterministic: true,
    });

    // Verify with binary message
    const isValid = verify(signature, msgBytes, ring);
    expect(isValid).toBe(true);

    // Verify with string message - should be valid as the content is the same
    const isValidWithString = verify(signature, msgString, ring);
    expect(isValidWithString).toBe(true);
  });
});
