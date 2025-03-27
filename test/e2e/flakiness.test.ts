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
  test("Flakiness Test E2E 10 times", () => {
    console.log("Running Flakiness Test 10 times");
    const iterations = 10;
    for (let i = 0; i < iterations; i++) {
      runFlakinessTest(i);
    }
  });
});

function runFlakinessTest(iterations: number) {
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

  const isValid = verify(signature, message, ring);

  console.log(`Iteration ${iterations} - ${isValid ? "Valid" : "Invalid"}`);
}
