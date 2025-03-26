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

describe("E2E: Nostringer ring signatures", () => {
  test("Sign & verify across multiple rings", () => {
    // Create ring #1 with deterministic keys
    const keyPairA = generateDeterministicKeyPair(1);
    const keyPairB = generateDeterministicKeyPair(2);
    const ring1 = [keyPairA.publicKeyHex, keyPairB.publicKeyHex];

    // Create another ring #2 with deterministic keys
    const keyPairC = generateDeterministicKeyPair(3);
    const keyPairD = generateDeterministicKeyPair(4);
    const ring2 = [keyPairC.publicKeyHex, keyPairD.publicKeyHex];

    const message = "End-to-end ring signature test";

    // Sign in ring1 as keyPairA with deterministic mode
    const sig1 = sign(message, keyPairA.privateKeyHex, ring1, {
      deterministic: true,
      debug: true,
    });
    expect(verify(sig1, message, ring1, { debug: true })).toBe(true);

    // Should fail in ring2
    expect(verify(sig1, message, ring2)).toBe(false);

    // Sign in ring2 as keyPairD with deterministic mode
    const sig2 = sign(message, keyPairD.privateKeyHex, ring2, {
      deterministic: true,
    });
    expect(verify(sig2, message, ring2)).toBe(true);

    // Should fail in ring1
    expect(verify(sig2, message, ring1)).toBe(false);
  });

  test("Complex scenario with multiple rings and members", () => {
    // Generate several deterministic keypairs
    const keyPairs = Array.from({ length: 6 }, (_, i) =>
      generateDeterministicKeyPair(i + 1),
    );

    // Create different rings using these keypairs
    const ringA = [
      keyPairs[0].publicKeyHex,
      keyPairs[1].publicKeyHex,
      keyPairs[2].publicKeyHex,
    ];
    const ringB = [
      keyPairs[3].publicKeyHex,
      keyPairs[4].publicKeyHex,
      keyPairs[5].publicKeyHex,
    ];
    const ringC = [keyPairs[0].publicKeyHex, keyPairs[3].publicKeyHex]; // Overlapping members

    const messageA = "Message for ring A";
    const messageB = "Message for ring B";
    const messageC = "Message for ring C";

    // Sign with each ring using deterministic mode and debug for ringB
    const sigA = sign(messageA, keyPairs[1].privateKeyHex, ringA, {
      deterministic: true,
    });
    const sigB = sign(messageB, keyPairs[5].privateKeyHex, ringB, {
      deterministic: true,
      debug: true,
    });
    const sigC = sign(messageC, keyPairs[0].privateKeyHex, ringC, {
      deterministic: true,
    });

    // Verify correct signatures with debug for ringB
    expect(verify(sigA, messageA, ringA)).toBe(true);
    expect(verify(sigB, messageB, ringB, { debug: true })).toBe(true);
    expect(verify(sigC, messageC, ringC)).toBe(true);

    // Verify incorrect combinations
    expect(verify(sigA, messageA, ringB)).toBe(false); // Wrong ring
    expect(verify(sigA, messageB, ringA)).toBe(false); // Wrong message
    expect(verify(sigB, messageB, ringC)).toBe(false); // Wrong ring

    // Try to verify in a subset of the correct ring
    const partialRingA = [keyPairs[0].publicKeyHex, keyPairs[1].publicKeyHex]; // Missing one member
    expect(verify(sigA, messageA, partialRingA)).toBe(false);
  });
});
