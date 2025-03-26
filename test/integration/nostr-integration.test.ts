import { sign, verify } from "../../src/index";
import { expect, test, describe } from "@jest/globals";
import {
  generateSecretKey,
  getPublicKey as nostrGetPublicKey,
} from "nostr-tools";
import { bytesToHex } from "@noble/hashes/utils";

// Helper function to convert Uint8Array to hex string
function uint8ArrayToHex(array: Uint8Array): string {
  return bytesToHex(array);
}

// Debug function to inspect keys and signatures
function debugLog(label: string, data: any) {
  console.log(`\n------ ${label} ------`);
  console.log(data);
  console.log("-".repeat(label.length + 14));
}

describe("Nostr Integration Tests", () => {
  test("Simple ring signature with nostr-tools generated keys", () => {
    // Generate just 2 keys for simplicity
    const sk1 = generateSecretKey();
    const pk1 = nostrGetPublicKey(sk1);
    const sk2 = generateSecretKey();
    const pk2 = nostrGetPublicKey(sk2);

    debugLog("Nostr Public Key 1", pk1);
    debugLog("Nostr Public Key 2", pk2);

    // Make sure these are all hex strings of the right length
    expect(typeof pk1).toBe("string");
    expect(pk1.length).toBe(64);
    expect(typeof pk2).toBe("string");
    expect(pk2.length).toBe(64);

    const ring = [pk1, pk2];
    const message = "Simple test message";

    // Convert private key to hex
    const skHex = uint8ArrayToHex(sk1);
    debugLog("Private Key Hex", skHex);

    // Sign message
    const signature = sign(message, skHex, ring);
    debugLog("Signature", signature);

    // Verify
    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);
  });

  test("Ring signature with nostr-tools generated keys", () => {
    // Generate 3 random Nostr keypairs using nostr-tools
    const sk1 = generateSecretKey();
    const pk1 = nostrGetPublicKey(sk1);
    const sk2 = generateSecretKey();
    const pk2 = nostrGetPublicKey(sk2);
    const sk3 = generateSecretKey();
    const pk3 = nostrGetPublicKey(sk3);

    // Create a ring of public keys
    const ring = [pk1, pk2, pk3];
    const message = "Message signed with nostr keys";

    // Sign with the second keypair (sk2)
    // Convert from Uint8Array to hex string for our library
    const skHex = uint8ArrayToHex(sk2);
    const signature = sign(message, skHex, ring);

    // Verify signature is valid
    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);

    // Verify signature fails with wrong message
    const wrongMessage = "Wrong message";
    const isInvalidWithWrongMessage = verify(signature, wrongMessage, ring);
    expect(isInvalidWithWrongMessage).toBe(false);

    // Verify signature fails with modified ring
    const modifiedRing = [pk1, pk3]; // remove pk2
    const isInvalidWithModifiedRing = verify(signature, message, modifiedRing);
    expect(isInvalidWithModifiedRing).toBe(false);
  });

  test("Unlinkability of multiple signatures using the same Nostr key", () => {
    // Generate 3 Nostr keypairs
    const sk1 = generateSecretKey();
    const pk1 = nostrGetPublicKey(sk1);
    const sk2 = generateSecretKey();
    const pk2 = nostrGetPublicKey(sk2);
    const sk3 = generateSecretKey();
    const pk3 = nostrGetPublicKey(sk3);

    const ring = [pk1, pk2, pk3];
    const message = "Testing unlinkability with Nostr keys";

    // Create two signatures with the same private key
    const skHex = uint8ArrayToHex(sk1);
    const sig1 = sign(message, skHex, ring);
    const sig2 = sign(message, skHex, ring);

    // Both should be valid
    expect(verify(sig1, message, ring)).toBe(true);
    expect(verify(sig2, message, ring)).toBe(true);

    // But they should be different (unlinkability property)
    expect(sig1).not.toEqual(sig2);
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

  test("Large ring with multiple Nostr keys", () => {
    // Generate a larger number of keys for a bigger ring
    const keyPairs = Array.from({ length: 5 }, () => {
      const sk = generateSecretKey();
      return {
        privateKey: sk,
        publicKey: nostrGetPublicKey(sk),
      };
    });

    // Create a ring with all public keys
    const ring = keyPairs.map((kp) => kp.publicKey);
    const message = "Message signed in a large Nostr ring";

    // Pick a random key to sign with
    const signerIndex = Math.floor(Math.random() * keyPairs.length);
    const signer = keyPairs[signerIndex];

    // Sign the message
    const skHex = uint8ArrayToHex(signer.privateKey);
    const signature = sign(message, skHex, ring);

    // Verify signature
    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);

    // Verify the c0 value is not null or empty
    expect(signature.c0).toBeTruthy();

    // Verify we have the right number of s values
    expect(signature.s.length).toBe(ring.length);
  });

  test("Cross-verification with mixed key generation methods", () => {
    // Generate some keys with nostr-tools
    const nostrSk = generateSecretKey();
    const nostrPk = nostrGetPublicKey(nostrSk);
    const nostrSkHex = uint8ArrayToHex(nostrSk);

    // Use existing nostringer key generation
    const nativeKeyPair = {
      privateKeyHex:
        "0000000000000000000000000000000000000000000000000000000000000001",
      publicKeyHex:
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    };

    // Create a mixed ring
    const ring = [nostrPk, nativeKeyPair.publicKeyHex];
    const message = "Message for cross-verification";

    // Sign with nostr-generated key
    const sig1 = sign(message, nostrSkHex, ring);
    expect(verify(sig1, message, ring)).toBe(true);

    // Sign with native key
    const sig2 = sign(message, nativeKeyPair.privateKeyHex, ring);
    expect(verify(sig2, message, ring)).toBe(true);
  });
});
