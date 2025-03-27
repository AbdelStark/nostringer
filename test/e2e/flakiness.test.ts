import { sign, verify } from "../../src/index";
import { test, describe } from "@jest/globals";
import { NostrTools } from "../helpers";

// Debug function to inspect keys and signatures
function debugLog(label: string, data: any) {
  console.log(`\n------ ${label} ------`);
  console.log(data);
  console.log("-".repeat(label.length + 14));
}

describe("Flakiness Tests", () => {
  test("Flakiness Test E2E 100 times", () => {
    console.log("Running Flakiness Test 100 times");
    const iterations = 100;
    for (let i = 0; i < iterations; i++) {
      runFlakinessTest(i);
    }
  });
});

function runFlakinessTest(iterations: number) {
  // Generate two Nostr keypairs using our helper
  const keyPairs = NostrTools.generateKeyPairs(3);

  debugLog("Key Pair 1", keyPairs[0]);
  debugLog("Key Pair 2", keyPairs[1]);
  debugLog("Key Pair 3", keyPairs[2]);
  // Create a ring with public keys 1 and 2
  const ring = [keyPairs[0].publicKeyHex, keyPairs[1].publicKeyHex];
  const message = "Test integration with nostr-tools keys";

  // Sign with the first private key
  const signature = sign(message, keyPairs[0].privateKeyHex, ring);
  debugLog("Signature", signature);

  const isValid = verify(signature, message, ring);

  console.log(`Iteration ${iterations} - ${isValid ? "Valid" : "Invalid"}`);

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
