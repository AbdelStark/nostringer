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
  for (const key of publicKeys) {
    buffers.push(hexToBytes(key));
  }

  // Add commitment point
  buffers.push(commitmentPoint.toRawBytes(true));

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
  return BigInt("0x" + bytesToHex(hash)) % N;
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
    // Validate private key
    if (!/^[0-9A-Fa-f]{64}$/.test(privateKeyHex)) {
      throw new Error("Private key must be 32-byte hex (64 hex chars)");
    }

    // Normalize inputs
    const privateKey = normalizeHex(privateKeyHex);
    const publicKeys = publicKeysHex.map((key) => normalizeHex(key));

    // Convert publicKeys to Points
    const ringPoints = publicKeys.map(hexToPoint);

    const ringSize = ringPoints.length;
    if (ringSize < 2) {
      throw new Error("Ring must have at least 2 participants for anonymity");
    }

    // Find signer's position in the ring
    const privateKeyScalar = hexToBigInt(privateKey);
    const signerPubKey = getPublicKey(privateKey);
    const signerIndex = publicKeys.findIndex(
      (pk) => pk.toLowerCase() === signerPubKey.toLowerCase()
    );

    if (signerIndex === -1) {
      throw new Error("Ring must include the signer's public key");
    }

    // Initialize arrays for responses (R) and challenges (C)
    const R: bigint[] = new Array(ringSize); // responses
    const C: bigint[] = new Array(ringSize); // challenges

    // Generate random scalar (alpha) for commitment
    const alpha = randomScalar();

    // Compute the commitment point alpha * G
    const alphaG = G.multiply(alpha);

    // Start the ring signature at index after signer
    const startIndex = (signerIndex + 1) % ringSize;

    // Compute the first challenge
    C[startIndex] = hashToScalar(message, publicKeys, alphaG);

    // Generate random responses for non-signer positions and compute challenges
    for (let i = startIndex; i !== signerIndex; i = (i + 1) % ringSize) {
      // Generate a random scalar as response
      R[i] = randomScalar();

      // Compute commitment: r_i * G + C[i] * P[i]
      const rG = G.multiply(R[i]);
      const cP = ringPoints[i].multiply(C[i]);
      const commitment = rG.add(cP);

      // Compute next challenge
      C[(i + 1) % ringSize] = hashToScalar(message, publicKeys, commitment);
    }

    // Close the ring by computing signer's response
    // R[signerIndex] = alpha - C[signerIndex] * privateKey mod N
    R[signerIndex] = mod(alpha - C[signerIndex] * privateKeyScalar);

    // Format responses as hex strings
    const responses = R.map((r) => r.toString(16).padStart(64, "0"));

    // Create signature object
    return {
      c0: C[0].toString(16).padStart(64, "0"),
      s: responses,
    };
  } catch (error) {
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
      return false;
    }

    const { c0, s } = signature;
    const ringSize = publicKeysHex.length;

    if (!c0 || !s || !Array.isArray(s) || s.length !== ringSize) {
      return false;
    }

    // Check for invalid message type
    if (!(typeof message === "string" || message instanceof Uint8Array)) {
      return false;
    }

    try {
      // Normalize public keys
      const publicKeys = publicKeysHex.map((key) => normalizeHex(key));

      // Convert publicKeys to Points
      const ringPoints = publicKeys.map(hexToPoint);

      // Convert challenges and responses to BigInt
      let c = hexToBigInt(c0);
      const R = s.map((val) => hexToBigInt(val));

      // Verify the ring signature
      for (let i = 0; i < ringSize; i++) {
        // Compute r_i * G + c_i * P_i
        const rG = G.multiply(R[i]);
        const cP = ringPoints[i].multiply(c);
        const commitment = rG.add(cP);

        // Compute the next challenge
        c = hashToScalar(message, publicKeys, commitment);
      }

      // Check if the ring closes correctly: final c should equal c0
      return c === hexToBigInt(c0);
    } catch (error) {
      return false;
    }
  } catch (error) {
    return false;
  }
}
