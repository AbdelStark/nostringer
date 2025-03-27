import { ProjectivePoint } from "@noble/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as secp from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha256";

// Define our types
export interface RingSignature {
  c0: string;
  s: string[];
}

// Curve parameters
const CURVE = secp.CURVE;
const N = CURVE.n; // Order of the curve
const G = ProjectivePoint.BASE; // Base point

/**
 * Normalize a hex string by removing 0x prefix, ensuring even length,
 * and handling case consistency
 */
function normalizeHex(hex: string): string {
  if (typeof hex !== "string") {
    throw new Error("Invalid hex string: not a string");
  }

  // Remove 0x prefix if present
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    hex = hex.slice(2);
  }

  // Convert to lowercase for consistency
  hex = hex.toLowerCase();

  // Check for non-hex characters
  if (!/^[0-9a-f]+$/.test(hex)) {
    throw new Error(`Invalid hex string: contains non-hex characters: ${hex}`);
  }

  // Ensure even length by padding with a leading zero if needed
  if (hex.length % 2 === 1) {
    hex = "0" + hex;
  }

  // Check for reasonable length for a key (32 bytes = 64 hex chars)
  if (hex.length > 128) {
    throw new Error(`Hex string too long: ${hex.length} chars`);
  }

  // Enforce 64 characters for public keys by padding with leading zeros
  // This is important for consistent key format across the library
  if (hex.length === 63) {
    hex = "0" + hex;
  }

  return hex;
}

/**
 * Convert a hex string to a BigInt
 */
function hexToBigInt(hex: string): bigint {
  return BigInt("0x" + normalizeHex(hex));
}

/**
 * Convert a hex string public key to a secp256k1 Point
 * Supports x-only (64 hex chars) or compressed keys with careful validation
 */
function hexToPoint(pubKeyHex: string): ProjectivePoint {
  try {
    // Normalize and validate the format
    const hex = normalizeHex(pubKeyHex);

    // Handle different key formats
    let fullHex: string;

    if (hex.length === 64) {
      // It's an x-only key (32 bytes / 64 hex chars), add 02 prefix for even y
      fullHex = "02" + hex;
    } else if (
      hex.length === 66 &&
      (hex.startsWith("02") || hex.startsWith("03"))
    ) {
      // Already in compressed format
      fullHex = hex;
    } else {
      throw new Error(`Unsupported public key format: ${hex.length} hex chars`);
    }

    try {
      const point = ProjectivePoint.fromHex(fullHex);

      // Validate the point is on curve
      if (!point.assertValidity()) {
        throw new Error("Point is not on the curve");
      }

      return point;
    } catch (err) {
      throw new Error(
        `Failed to create point from hex: ${
          err instanceof Error ? err.message : String(err)
        }`
      );
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Invalid public key: ${error.message}`);
    }
    throw new Error(`Invalid public key: unknown error`);
  }
}

/**
 * Generate a random scalar (a number between 1 and n-1)
 */
function randomScalar(): bigint {
  let scalar: bigint;
  do {
    const privateKey = secp.utils.randomPrivateKey();
    scalar = BigInt("0x" + bytesToHex(privateKey));
  } while (scalar === 0n || scalar >= N);
  return scalar;
}

/**
 * Compute hash of message and points for challenge generation
 * Returns a BigInt scalar mod N
 */
function hashToScalar(
  message: string | Uint8Array,
  publicKeys: string[],
  commitmentPoint: ProjectivePoint
): bigint {
  try {
    // Convert message to bytes
    let msgBytes: Uint8Array;
    if (typeof message === "string") {
      msgBytes = new TextEncoder().encode(message);
    } else if (message instanceof Uint8Array) {
      msgBytes = message;
    } else {
      throw new Error("Message must be a string or Uint8Array");
    }

    // Create buffer for all data
    const buffers: Uint8Array[] = [msgBytes];

    // Add all public keys (important for ring binding)
    // Make sure each key is normalized consistently
    for (const key of publicKeys) {
      const normalizedKey = normalizeHex(key);
      buffers.push(hexToBytes(normalizedKey));
    }

    // Add commitment point with consistent serialization
    // Using compressed format for points ensures deterministic results
    const pointBytes = commitmentPoint.toRawBytes(true);
    buffers.push(pointBytes);

    // Combine all data
    let totalLength = 0;
    for (const buffer of buffers) {
      totalLength += buffer.length;
    }

    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const buffer of buffers) {
      combined.set(buffer, offset);
      offset += buffer.length;
    }

    // Hash and convert to scalar mod N
    const hash = sha256(combined);
    const scalar = BigInt("0x" + bytesToHex(hash)) % N;

    return scalar === 0n ? 1n : scalar; // Ensure non-zero scalar
  } catch (error) {
    console.error("Error in hashToScalar:", error);
    throw error;
  }
}

/**
 * Apply modulo n to ensure value is within the range [0, n-1]
 */
function mod(a: bigint, n: bigint = N): bigint {
  const result = a % n;
  return result >= 0n ? result : result + n;
}

/**
 * Generate a random private key
 * @returns A hex string representing a random private key
 */
export function generatePrivateKey(): string {
  return bytesToHex(secp.utils.randomPrivateKey());
}

/**
 * Get public key from private key (x-only format)
 * @param privateKeyHex - The private key as a hex string
 * @returns The x-only public key as a hex string
 */
export function getPublicKey(privateKeyHex: string): string {
  try {
    const normalizedPrivKey = normalizeHex(privateKeyHex);
    if (normalizedPrivKey.length !== 64) {
      throw new Error(
        `Invalid private key length: got ${normalizedPrivKey.length} hex chars, expected 64`
      );
    }

    const privBytes = hexToBytes(normalizedPrivKey);
    if (privBytes.length !== 32) {
      throw new Error(
        `Invalid private key byte length: got ${privBytes.length} bytes, expected 32`
      );
    }

    const point = ProjectivePoint.fromPrivateKey(privBytes);
    // Ensure consistent formatting with padStart for public key
    const publicKeyHex = point.x.toString(16).padStart(64, "0");

    // Validate result format
    if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) {
      throw new Error(`Invalid public key format: ${publicKeyHex}`);
    }

    return publicKeyHex;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Error deriving public key: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Sign a message using SAG ring signature scheme
 *
 * @param message - The message to sign
 * @param privateKeyHex - The signer's private key in hex
 * @param publicKeysHex - Array of public keys in the ring
 * @returns Ring signature object with c0 and responses
 */
export function sign(
  message: string | Uint8Array,
  privateKeyHex: string,
  publicKeysHex: string[]
): RingSignature {
  try {
    // Validate private key format
    if (!/^[0-9A-Fa-f]{64}$/.test(privateKeyHex)) {
      throw new Error("Private key must be 32-byte hex (64 hex chars)");
    }

    console.log("sign >> Private Key", privateKeyHex);

    // Normalize inputs consistently
    const normalizedPrivKey = normalizeHex(privateKeyHex);
    console.log("sign >> Normalized Private Key", normalizedPrivKey);
    const publicKeys = publicKeysHex.map((key) => normalizeHex(key));
    console.log("sign >> Normalized Public Keys", publicKeys);

    // Convert publicKeys to Points
    const ringPoints = publicKeys.map((key) => {
      try {
        return hexToPoint(key);
      } catch (error) {
        console.error(`Error converting public key to point: ${key}`, error);
        throw error;
      }
    });

    console.log("sign >> Ring Points", ringPoints);

    const ringSize = ringPoints.length;
    if (ringSize < 2) {
      throw new Error("Ring must have at least 2 participants for anonymity");
    }

    // Find signer's position in the ring
    const privateKeyScalar = hexToBigInt(normalizedPrivKey);
    console.log("sign >> Private Key Scalar", privateKeyScalar);
    const signerPubKey = getPublicKey(normalizedPrivKey);
    console.log("sign >> Signer Public Key", signerPubKey);
    const signerIndex = publicKeys.findIndex(
      (pk) => pk.toLowerCase() === signerPubKey.toLowerCase()
    );
    console.log("sign >> Signer Index", signerIndex);
    if (signerIndex === -1) {
      throw new Error("Ring must include the signer's public key");
    }

    // Initialize arrays for responses (R) and challenges (C)
    const R: bigint[] = new Array(ringSize); // responses
    const C: bigint[] = new Array(ringSize); // challenges

    // Generate random scalar (alpha) for commitment
    const alpha = randomScalar();
    console.log("sign >> Alpha", alpha);
    // Compute the commitment point alpha * G
    const alphaG = G.multiply(alpha);
    console.log("sign >> Alpha * G", alphaG);
    // Start the ring signature at index after signer
    const startIndex = (signerIndex + 1) % ringSize;
    console.log("sign >> Start Index", startIndex);
    // Compute the first challenge
    C[startIndex] = hashToScalar(message, publicKeys, alphaG);
    console.log("sign >> C[startIndex]", C[startIndex]);

    // Generate random responses for non-signer positions and compute challenges
    for (let i = startIndex; i !== signerIndex; i = (i + 1) % ringSize) {
      // Generate a random scalar as response
      R[i] = randomScalar();
      console.log("sign >> R[i]", R[i]);
      // Compute commitment: r_i * G + C[i] * P[i]
      const rG = G.multiply(R[i]);
      console.log("sign >> rG", rG);
      const cP = ringPoints[i].multiply(C[i]);
      console.log("sign >> cP", cP);
      const commitment = rG.add(cP);
      console.log("sign >> commitment", commitment);
      // Compute next challenge
      C[(i + 1) % ringSize] = hashToScalar(message, publicKeys, commitment);
      console.log("sign >> C[(i + 1) % ringSize]", C[(i + 1) % ringSize]);
    }

    // Close the ring by computing signer's response
    // R[signerIndex] = alpha - C[signerIndex] * privateKey mod N
    R[signerIndex] = mod(alpha - C[signerIndex] * privateKeyScalar);
    console.log("sign >> R[signerIndex]", R[signerIndex]);
    // Format responses as hex strings
    const responses = R.map((r) => r.toString(16).padStart(64, "0"));

    // Create signature object
    return {
      c0: C[0].toString(16).padStart(64, "0"),
      s: responses,
    };
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Signing error: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Verify a ring signature
 *
 * @param signature - Ring signature object with c0 and s values
 * @param message - The message that was signed
 * @param publicKeysHex - Array of public keys in the ring
 * @returns True if signature is valid, false otherwise
 */
export function verify(
  signature: RingSignature,
  message: string | Uint8Array,
  publicKeysHex: string[]
): boolean {
  try {
    // Basic validation
    if (
      !signature ||
      !message ||
      !publicKeysHex ||
      !Array.isArray(publicKeysHex)
    ) {
      console.error("Verification failed: invalid inputs");
      return false;
    }

    console.log("verify >> Signature", signature);
    console.log("verify >> Message", message);
    console.log("verify >> Public Keys", publicKeysHex);

    const { c0, s } = signature;
    const ringSize = publicKeysHex.length;

    if (!c0 || !s || !Array.isArray(s) || s.length !== ringSize) {
      console.error("Verification failed: invalid signature format");
      return false;
    }

    // Check for invalid message type
    if (!(typeof message === "string" || message instanceof Uint8Array)) {
      console.error("Verification failed: invalid message type");
      return false;
    }

    try {
      // Normalize public keys and signature values consistently
      const publicKeys = publicKeysHex.map((key) => normalizeHex(key));
      console.log("verify >> Normalized Public Keys", publicKeys);
      const normalizedC0 = normalizeHex(c0);
      console.log("verify >> Normalized C0", normalizedC0);
      const normalizedS = s.map((val) => normalizeHex(val));
      console.log("verify >> Normalized S", normalizedS);

      // Convert publicKeys to Points
      const ringPoints = publicKeys.map((key) => {
        try {
          return hexToPoint(key);
        } catch (error) {
          console.error(`Error converting public key to point: ${key}`, error);
          throw error;
        }
      });
      console.log("verify >> Ring Points", ringPoints);

      // Convert challenges and responses to BigInt
      let c = hexToBigInt(normalizedC0);
      console.log("verify >> C", c);
      const R = normalizedS.map((val) => hexToBigInt(val));
      console.log("verify >> R", R);

      // Verify the ring signature
      for (let i = 0; i < ringSize; i++) {
        try {
          // Compute commitment: r_i * G + c_i * P_i
          const rG = G.multiply(R[i]);
          console.log("verify >> rG", rG);
          const cP = ringPoints[i].multiply(c);
          console.log("verify >> cP", cP);
          const commitment = rG.add(cP);
          console.log("verify >> commitment", commitment);

          // Compute the next challenge
          c = hashToScalar(message, publicKeys, commitment);
          console.log("verify >> c", c);
        } catch (error) {
          console.error(`Error in verification loop at index ${i}:`, error);
          return false;
        }
      }

      // Check if the ring closes correctly: final c should equal c0
      const initialC = hexToBigInt(normalizedC0);
      console.log("verify >> Initial C", initialC);
      if (c === initialC) {
        console.log("verify >> Verification successful");
        return true;
      } else {
        console.error("Verification failed: ring did not close correctly");
        return false;
      }
    } catch (error) {
      console.error("Verification error:", error);
      return false;
    }
  } catch (error) {
    console.error("Outer verification error:", error);
    return false;
  }
}
