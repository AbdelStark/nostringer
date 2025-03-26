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

describe("E2E: Nostringer ring signatures", () => {
  test("Sign & verify across multiple rings", () => {
    // Create ring #1
    const keyPairA = generateKeyPair();
    const keyPairB = generateKeyPair();
    const ring1 = [keyPairA.publicKeyHex, keyPairB.publicKeyHex];

    // Create another ring #2
    const keyPairC = generateKeyPair();
    const keyPairD = generateKeyPair();
    const ring2 = [keyPairC.publicKeyHex, keyPairD.publicKeyHex];

    const message = "End-to-end ring signature test";

    // Sign in ring1 as keyPairA
    const sig1 = sign(message, keyPairA.privateKeyHex, ring1);
    expect(verify(sig1, message, ring1)).toBe(true);
    // Should fail in ring2
    expect(verify(sig1, message, ring2)).toBe(false);

    // Sign in ring2 as keyPairD
    const sig2 = sign(message, keyPairD.privateKeyHex, ring2);
    expect(verify(sig2, message, ring2)).toBe(true);
    // Should fail in ring1
    expect(verify(sig2, message, ring1)).toBe(false);
  });

  test("Complex scenario with multiple rings and members", () => {
    // Generate several keypairs
    const keyPairs = Array.from({ length: 6 }, () => generateKeyPair());

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

    // Sign with each ring
    const sigA = sign(messageA, keyPairs[1].privateKeyHex, ringA); // Signer from ring A
    const sigB = sign(messageB, keyPairs[5].privateKeyHex, ringB); // Signer from ring B
    const sigC = sign(messageC, keyPairs[0].privateKeyHex, ringC); // Signer from ring C

    // Verify correct signatures
    expect(verify(sigA, messageA, ringA)).toBe(true);
    expect(verify(sigB, messageB, ringB)).toBe(true);
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
