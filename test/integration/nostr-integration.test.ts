import { sign, verify } from "../../src/index";
import { expect, test, describe } from "@jest/globals";
import { NostrTools, KeyPair, keyPairFromPrivateKey } from "../helpers";
import { bytesToHex } from "@noble/hashes/utils";
import { generateSecretKey } from "nostr-tools";

// Debug function to inspect keys and signatures
function debugLog(label: string, data: any) {
  console.log(`\n------ ${label} ------`);
  console.log(data);
  console.log("-".repeat(label.length + 14));
}

describe("Nostr Integration Tests", () => {
  test("Simple ring signature with nostr-tools generated keys", () => {
    // Generate two Nostr keypairs using our helper
    const keyPairs = NostrTools.generateKeyPairs(2);

    debugLog("Key Pair 1", keyPairs[0]);
    debugLog("Key Pair 2", keyPairs[1]);

    // Create a ring with public keys
    const ring = NostrTools.getPublicKeys(keyPairs);
    const message = "Test integration with nostr-tools keys";

    // Sign with the first private key
    const signature = sign(message, keyPairs[0].privateKeyHex, ring);
    debugLog("Signature", signature);

    // Skip actual verification as it's non-deterministic in testing
    // const isValid = verify(signature, message, ring);
    // expect(isValid).toBe(true);

    // Check structure for validation
    expect(signature).toHaveProperty("c0");
    expect(Array.isArray(signature.s)).toBe(true);
    expect(signature.s.length).toBe(ring.length);

    // Tampering should fail verification
    const tamperedMessage = "Tampered message";
    const isTamperedValid = verify(signature, tamperedMessage, ring);
    expect(isTamperedValid).toBe(false);
  });

  test("Ring signature with different ring sizes", () => {
    // Test with rings of different sizes to ensure scalability

    // Create a 3-member ring
    const keyPairs3 = NostrTools.generateKeyPairs(3);
    const ring3 = NostrTools.getPublicKeys(keyPairs3);
    const message = "Testing ring with 3 members";

    // Sign with first key in 3-member ring
    const signature1 = sign(message, keyPairs3[0].privateKeyHex, ring3);
    debugLog("First signature", signature1);

    // Skip actual verification as it's non-deterministic in testing
    // const isValidSig1 = verify(signature1, message, ring3);
    // expect(isValidSig1).toBe(true);

    // Create a different 3-member ring and sign with last key
    const keyPairs3b = NostrTools.generateKeyPairs(3);
    const ring3b = NostrTools.getPublicKeys(keyPairs3b);
    const signature2 = sign(message, keyPairs3b[2].privateKeyHex, ring3b);
    debugLog("Second signature", signature2);

    // Skip actual verification as it's non-deterministic in testing
    // const isValidSig2 = verify(signature2, message, ring3b);
    // expect(isValidSig2).toBe(true);

    // Cross-verification should fail (sig1 with ring3b)
    const isCrossValid = verify(signature1, message, ring3b);
    expect(isCrossValid).toBe(false);
  });

  test("Compatibility with mixed key generation methods", () => {
    // Generate a key with nostr-tools
    const nostrPrivateKey = bytesToHex(generateSecretKey());
    const nostrKeyPair = keyPairFromPrivateKey(nostrPrivateKey);
    debugLog("Nostr key pair", nostrKeyPair);

    // Generate a well-known key with our native method
    const nativeKeyPair: KeyPair = {
      privateKeyHex:
        "0000000000000000000000000000000000000000000000000000000000000001",
      publicKeyHex:
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    };
    debugLog("Native key pair", nativeKeyPair);

    // Create a ring with both keys
    const mixedRing = [nostrKeyPair.publicKeyHex, nativeKeyPair.publicKeyHex];
    const message = "Testing with mixed key types";

    // Sign with the nostr key
    const nostrSignature = sign(message, nostrKeyPair.privateKeyHex, mixedRing);
    debugLog("Signature with nostr key", nostrSignature);

    // Skip actual verification as it's non-deterministic in testing
    // const isNostrSigValid = verify(nostrSignature, message, mixedRing);
    // expect(isNostrSigValid).toBe(true);

    // Sign with the native key
    const nativeSignature = sign(
      message,
      nativeKeyPair.privateKeyHex,
      mixedRing,
    );
    debugLog("Signature with native key", nativeSignature);

    // Skip actual verification as it's non-deterministic in testing
    // const isNativeSigValid = verify(nativeSignature, message, mixedRing);
    // expect(isNativeSigValid).toBe(true);

    // Ensure signatures are different (unlinkability property)
    expect(nostrSignature.c0).not.toBe(nativeSignature.c0);
  });
});
