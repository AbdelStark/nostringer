import { sign, verify } from "../../src/index.js";
import { ProjectivePoint, utils } from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { expect, test, describe } from "@jest/globals";

describe("Simple Sign/Verify Tests", () => {
  // Generate a deterministic keypair
  function getDeterministicKeyPair() {
    // Fixed "1" private key (for reproducibility)
    const privateKeyHex =
      "0000000000000000000000000000000000000000000000000000000000000001";
    // Get bytes from hex
    const privateKeyBytes = hexToBytes(privateKeyHex);
    // Get public key point
    const pubPoint = ProjectivePoint.fromPrivateKey(privateKeyBytes);
    // Get x-only public key
    const publicKeyHex = pubPoint.x.toString(16).padStart(64, "0");

    // Return key pair
    return { privateKeyHex, publicKeyHex };
  }

  test("Basic sign and verify with 2-member ring", () => {
    // 1. Create fixed key for first ring member
    const keyPair1 = getDeterministicKeyPair();

    // 2. Create random key for second ring member
    const privateKey2 = utils.randomPrivateKey();
    const pubPoint2 = ProjectivePoint.fromPrivateKey(privateKey2);
    const keyPair2 = {
      privateKeyHex: bytesToHex(privateKey2),
      publicKeyHex: pubPoint2.x.toString(16).padStart(64, "0"),
    };

    // 3. Create the ring
    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    console.log("Ring:", ring);

    // 4. Create message
    const message = "test-message";

    // 5. Create signature using first key with deterministic option and debug
    const signature = sign(message, keyPair1.privateKeyHex, ring, {
      deterministic: true,
      debug: true,
    });
    console.log("Signature:", signature);

    // 6. Verify the signature with debug
    const isValid = verify(signature, message, ring, { debug: true });
    console.log("Verification result:", isValid);

    // This test should pass
    expect(isValid).toBe(true);
  });

  test("Non-deterministic signing also works", () => {
    // Use the same setup as above but with non-deterministic signing
    const keyPair1 = getDeterministicKeyPair();
    const privateKey2 = utils.randomPrivateKey();
    const pubPoint2 = ProjectivePoint.fromPrivateKey(privateKey2);
    const keyPair2 = {
      privateKeyHex: bytesToHex(privateKey2),
      publicKeyHex: pubPoint2.x.toString(16).padStart(64, "0"),
    };

    const ring = [keyPair1.publicKeyHex, keyPair2.publicKeyHex];
    const message = "test with random nonce";

    // Sign with regular random values
    const signature = sign(message, keyPair1.privateKeyHex, ring);

    // Verify
    const isValid = verify(signature, message, ring);
    expect(isValid).toBe(true);
  });
});
