import { ProjectivePoint } from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { generateSecretKey as nostrGenerateSecretKey } from "nostr-tools";

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
 * Create a key pair from a private key hex string
 * @param privateKeyHex - Private key as hex string
 * @returns A KeyPair object with private and public keys
 */
export function keyPairFromPrivateKey(privateKeyHex: string): KeyPair {
  const privateBytes = hexToBytes(privateKeyHex);
  const pubKey = ProjectivePoint.fromPrivateKey(privateBytes);
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

/**
 * Utility functions for working with nostr-tools
 */
export const NostrTools = {
  /**
   * Generate a nostr key pair using nostr-tools and return it in a format compatible with our library
   * @returns A KeyPair object with private and public keys in hex format
   */
  generateKeyPair(): KeyPair {
    const privKey = nostrGenerateSecretKey();
    const privateKeyHex = bytesToHex(privKey);

    // Get the public key using our library's method instead of nostr-tools
    // This ensures the public key format is compatible with our ring signature implementation
    const pubKey = ProjectivePoint.fromPrivateKey(privKey);
    const publicKeyHex = pubKey.x.toString(16).padStart(64, "0");

    return { privateKeyHex, publicKeyHex };
  },

  /**
   * Generate multiple nostr key pairs
   * @param count Number of key pairs to generate (default: 3)
   * @returns An array of KeyPair objects
   */
  generateKeyPairs(count: number = 3): KeyPair[] {
    return Array.from({ length: count }, () => this.generateKeyPair());
  },

  /**
   * Extract just the public keys from an array of key pairs
   * @param keyPairs Array of KeyPair objects
   * @returns Array of public keys
   */
  getPublicKeys(keyPairs: KeyPair[]): string[] {
    return keyPairs.map((kp) => kp.publicKeyHex);
  },
};
