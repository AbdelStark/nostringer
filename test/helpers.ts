import { ProjectivePoint } from "@noble/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Interface for a key pair with private and public keys
 */
export interface KeyPair {
  privateKeyHex: string;
  publicKeyHex: string;
}

/**
 * Generate a deterministic key pair from a seed for testing
 * @param seed - Number to use as seed (default: 1)
 * @returns A KeyPair object with private and public keys
 */
export function generateDeterministicKeyPair(seed = 1): KeyPair {
  // Create a deterministic private key from the seed
  const seedBytes = new Uint8Array(32).fill(0);
  seedBytes[31] = seed;
  const privateKeyHex = bytesToHex(seedBytes);

  // Get the public key
  const pubKey = ProjectivePoint.fromPrivateKey(seedBytes);
  const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");

  return { privateKeyHex, publicKeyHex };
}

/**
 * Generate a random key pair for testing
 * @returns A KeyPair object with private and public keys
 */
export function generateRandomKeyPair(): KeyPair {
  // Use the window crypto API for secure randomness
  const privateBytes = new Uint8Array(32);
  crypto.getRandomValues(privateBytes);
  const privateKeyHex = bytesToHex(privateBytes);

  // Get the public key
  const pubKey = ProjectivePoint.fromPrivateKey(privateBytes);
  const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");

  return { privateKeyHex, publicKeyHex };
}
