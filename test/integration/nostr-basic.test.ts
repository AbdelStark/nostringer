import { sign, verify } from "../../src/index";
import { expect, test, describe } from "@jest/globals";
import { NostrTools } from "../helpers";

// This test file focuses purely on the correct integration with nostr-tools keys
// and ensuring the basic ring signature functionality works with them

describe("Basic Nostr Key Integration", () => {
  test("Ring signature with 2 nostr keys", () => {
    // Generate two Nostr keypairs using our helper
    const keyPairs = NostrTools.generateKeyPairs(2);

    // Create a simple ring with just the public keys
    const ring = NostrTools.getPublicKeys(keyPairs);
    const message = "Test message";

    // Sign with the first private key
    const signature = sign(message, keyPairs[0].privateKeyHex, ring);

    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);

    // Tampered message should fail verification
    const tamperedMessage = "Tampered message";
    const isTamperedValid = verify(signature, tamperedMessage, ring);
    expect(isTamperedValid).toBe(false);
  });

  test("Ring signature verification fails with incorrect message", () => {
    // Generate two Nostr keypairs
    const keyPairs = NostrTools.generateKeyPairs(2);
    const ring = NostrTools.getPublicKeys(keyPairs);

    const message = "Original message";
    const wrongMessage = "Wrong message";

    // Sign with the first private key
    const signature = sign(message, keyPairs[0].privateKeyHex, ring);

    // Verify with wrong message - should fail
    const isInvalid = verify(signature, wrongMessage, ring);
    expect(isInvalid).toBe(false);
  });

  test("Ring signature verification fails with modified ring", () => {
    // Generate three Nostr keypairs
    const keyPairs = NostrTools.generateKeyPairs(3);

    // Create original ring with first two keys
    const originalRing = [keyPairs[0].publicKeyHex, keyPairs[1].publicKeyHex];
    const message = "Test message";

    // Sign with the first private key
    const signature = sign(message, keyPairs[0].privateKeyHex, originalRing);

    // Verify with a modified ring (replace second key with third key)
    const modifiedRing = [keyPairs[0].publicKeyHex, keyPairs[2].publicKeyHex];
    const isInvalid = verify(signature, message, modifiedRing);
    expect(isInvalid).toBe(false);
  });
});
