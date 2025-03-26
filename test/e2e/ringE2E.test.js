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
    // Instead of using generateDeterministicKeyPair, create simple keypairs for more predictable results
    const keyPairs = [
      {
        privateKeyHex: "0000000000000000000000000000000000000000000000000000000000000001",
        publicKeyHex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      {
        privateKeyHex: "0000000000000000000000000000000000000000000000000000000000000002",
        publicKeyHex: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      {
        privateKeyHex: "0000000000000000000000000000000000000000000000000000000000000003",
        publicKeyHex: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      },
      {
        privateKeyHex: "0000000000000000000000000000000000000000000000000000000000000004", 
        publicKeyHex: "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
      },
      {
        privateKeyHex: "0000000000000000000000000000000000000000000000000000000000000005",
        publicKeyHex: "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
      },
      {
        privateKeyHex: "0000000000000000000000000000000000000000000000000000000000000006",
        publicKeyHex: "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
      }
    ];

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
    const sigA = sign(messageA, keyPairs[1].privateKeyHex, ringA);
    const sigB = sign(messageB, keyPairs[5].privateKeyHex, ringB);
    const sigC = sign(messageC, keyPairs[0].privateKeyHex, ringC);

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
  
  test("Signature uniqueness and unlinkability", () => {
    // Create a single ring with 3 members
    const keyPairA = generateDeterministicKeyPair(1);
    const keyPairB = generateDeterministicKeyPair(2);
    const keyPairC = generateDeterministicKeyPair(3);
    const ring = [keyPairA.publicKeyHex, keyPairB.publicKeyHex, keyPairC.publicKeyHex];
    
    const message = "Test message for unlinkability";
    
    // Sign the same message twice with the same key
    const sig1 = sign(message, keyPairA.privateKeyHex, ring);
    const sig2 = sign(message, keyPairA.privateKeyHex, ring);
    
    // Both signatures should be valid
    expect(verify(sig1, message, ring)).toBe(true);
    expect(verify(sig2, message, ring)).toBe(true);
    
    // But they should be different (due to randomness)
    expect(sig1.c0).not.toBe(sig2.c0);
    
    // At least one of the response values should differ
    let allSame = true;
    for (let i = 0; i < sig1.s.length; i++) {
      if (sig1.s[i] !== sig2.s[i]) {
        allSame = false;
        break;
      }
    }
    expect(allSame).toBe(false);
  });
});
