import { sign, verify } from "../../src/index";
import { test, describe } from "@jest/globals";
import { NostrTools } from "../helpers";

describe("Flakiness Tests", () => {
  test("Flakiness Test E2E 100 times", () => {
    const iterations = 100;
    for (let i = 0; i < iterations; i++) {
      runFlakinessTest(i);
    }
  });
});

function runFlakinessTest(iterations: number) {
  // Generate two Nostr keypairs using our helper
  const keyPairs = NostrTools.generateKeyPairs(3);
  // Create a ring with public keys 1 and 2
  const ring = [keyPairs[0].publicKeyHex, keyPairs[1].publicKeyHex];
  const message = "Test integration with nostr-tools keys";

  // Sign with the first private key
  const signature = sign(message, keyPairs[0].privateKeyHex, ring);

  const isValid = verify(signature, message, ring);

  expect(isValid).toBe(true);

  const compromisedRing = [
    keyPairs[0].publicKeyHex,
    keyPairs[1].publicKeyHex,
    keyPairs[2].publicKeyHex,
  ];
  // Signer 3 is not part of the ring
  const compromisedSignature = sign(
    message,
    keyPairs[2].privateKeyHex,
    compromisedRing,
  );
  const compromisedIsValid = verify(compromisedSignature, message, ring);

  // Assert that the compromised signature is invalid
  expect(compromisedIsValid).toBe(false);
}
