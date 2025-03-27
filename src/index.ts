import { ProjectivePoint } from "@noble/secp256k1";
import * as secp from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

/**
 * A ring signature output: initial challenge + array of response scalars.
 */
export interface RingSignature {
  c0: string;
  s: string[]; // each response is a 64-hex string
}

/**
 * Generate a new random key pair.
 * - Private key is returned in 64‑hex (32 bytes).
 * - Public key is returned as 66‑hex compressed (33 bytes).
 */
export function generateKeyPair(): {
  privateKeyHex: string;
  publicKeyHex: string;
} {
  // 1) Generate random 32‑byte secret
  const privBytes = secp.utils.randomPrivateKey(); // typed array
  const privHex = bytesToHex(privBytes);

  // 2) Convert to compressed public key (33 bytes, prefix 02 or 03)
  const pubPoint = ProjectivePoint.fromPrivateKey(privBytes);
  // `.toRawBytes(true)` => compressed
  const pubBytes = pubPoint.toRawBytes(true);
  const pubHex = bytesToHex(pubBytes); // 66 hex chars

  return {
    privateKeyHex: privHex,
    publicKeyHex: pubHex,
  };
}

// secp256k1 constants
const N = secp.CURVE.n; // order
const G = ProjectivePoint.BASE;

/**
 * Modular operation within [0, N-1].
 */
function mod(a: bigint, m: bigint = N): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/**
 * Normalize a hex string: remove `0x` prefix, make lowercase, ensure even length.
 * Throws if non-hex or absurdly long.
 */
function normalizeHex(hex: string): string {
  if (typeof hex !== "string") {
    throw new Error("Not a string");
  }
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    hex = hex.slice(2);
  }
  hex = hex.toLowerCase();
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`Non-hex characters found in: ${hex}`);
  }
  if (hex.length % 2 === 1) {
    hex = "0" + hex;
  }
  if (hex.length > 130) {
    // longer than an uncompressed 65‑byte key = 130 hex
    throw new Error(`Hex string length too large: ${hex.length}`);
  }
  return hex;
}

/**
 * Convert a hex string to a BigInt mod N.
 */
function hexToBigInt(h: string): bigint {
  const norm = normalizeHex(h);
  const val = BigInt("0x" + norm);
  return val % N;
}

/**
 * Parse a secp256k1 public key in standard SEC format:
 * - Compressed (33 bytes): length=66 hex, prefix=02 or 03
 * - Uncompressed (65 bytes): length=130 hex, prefix=04
 *
 * Throws if format is not recognized or point is invalid.
 */
function hexToPoint(pubKeyHex: string): ProjectivePoint {
  const hex = normalizeHex(pubKeyHex);

  if (hex.length === 66 && (hex.startsWith("02") || hex.startsWith("03"))) {
    // Compressed
    const point = ProjectivePoint.fromHex(hex);
    point.assertValidity();
    return point;
  } else if (hex.length === 130 && hex.startsWith("04")) {
    // Uncompressed
    const point = ProjectivePoint.fromHex(hex);
    point.assertValidity();
    return point;
  } else {
    throw new Error(
      `Public key must be 66-hex compressed (02 or 03) or 130-hex uncompressed (04). Got length=${
        hex.length
      }, prefix=${hex.slice(0, 2)}`
    );
  }
}

/**
 * Convert message + ring pubkeys + ephemeral point into a single buffer,
 * then sha256 => scalar mod N (never zero).
 */
function hashToScalar(
  message: string | Uint8Array,
  ringPubKeys: string[],
  point: ProjectivePoint
): bigint {
  let msgBytes: Uint8Array;
  if (typeof message === "string") {
    msgBytes = new TextEncoder().encode(message);
  } else {
    msgBytes = message;
  }

  const buffers: Uint8Array[] = [msgBytes];

  // Include each ring pubkey as raw bytes
  for (const pk of ringPubKeys) {
    const pkNorm = normalizeHex(pk);
    buffers.push(hexToBytes(pkNorm));
  }

  // Add ephemeral point in compressed form
  const ephemeralBytes = point.toRawBytes(true);
  buffers.push(ephemeralBytes);

  // Concatenate
  const totalLen = buffers.reduce((acc, b) => acc + b.length, 0);
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const b of buffers) {
    combined.set(b, offset);
    offset += b.length;
  }

  const h = sha256(combined);
  const s = BigInt("0x" + bytesToHex(h)) % N;
  return s === 0n ? 1n : s;
}

function convertXOnlyToCompressedIfRequired(input: string): string {
  if (input.length === 66) {
    return input;
  }
  return convertXOnlyToCompressed(input);
}

function convertXOnlyToCompressed(xOnlyHex: string): string {
  const isEvenY = isEvenBitwise(BigInt("0x" + xOnlyHex));
  // Prepend "02" if isEvenY, or "03" if it's odd.
  // But you'd need to know which Y parity to use for that x.
  return (isEvenY ? "02" : "03") + xOnlyHex;
}

function isEvenBitwise(bigIntNumber: bigint) {
  return (bigIntNumber & 1n) === 0n;
}

/**
 * Sign a message with an LSAG ring signature:
 * - `message`: the message (string or bytes)
 * - `privateKeyHex`: 64-hex (32 bytes)
 * - `ringPubKeysHex`: each a standard SEC key:
 *     - 66-hex compressed (starts '02' or '03') or
 *     - 130-hex uncompressed (starts '04')
 *
 * Returns { c0, s[] } with each field 64-hex.
 */
export function sign(
  message: string | Uint8Array,
  privateKeyHex: string,
  ringPubKeysHex: string[]
): RingSignature {
  // Basic checks
  const privHexNorm = normalizeHex(privateKeyHex);

  // Convert private key to compressed if needed
  if (privHexNorm.length !== 64) {
    throw new Error(
      `Private key must be 32-byte hex => 64 chars. Got length=${privHexNorm.length}`
    );
  }

  // Convert ring pubkeys to points
  const ringPoints = ringPubKeysHex.map(hexToPoint);
  const ringSize = ringPoints.length;
  if (ringSize < 2) {
    throw new Error("Ring must have at least 2 members");
  }

  // Convert privKey => BigInt
  const x = BigInt("0x" + privHexNorm);

  // Derive the actual public key from x (to see which ring index is ours)
  const myPoint = ProjectivePoint.fromPrivateKey(hexToBytes(privHexNorm));
  myPoint.assertValidity();
  const myPubCompressed = bytesToHex(myPoint.toRawBytes(true)).toLowerCase();

  // Find our index in the ring
  const signerIndex = ringPubKeysHex.findIndex(
    (pk) => normalizeHex(pk) === myPubCompressed
  );
  if (signerIndex < 0) {
    throw new Error("Ring does not contain this private key’s public key");
  }

  // Arrays for responses & challenges
  const R: bigint[] = new Array(ringSize);
  const C: bigint[] = new Array(ringSize);

  // Pick random alpha => alphaG
  const alpha = randomScalar();
  const alphaG = G.multiply(alpha);

  // c_(start) = hashToScalar( message, ringPubKeysHex, alphaG )
  const startIndex = (signerIndex + 1) % ringSize;
  C[startIndex] = hashToScalar(message, ringPubKeysHex, alphaG);

  // Fill random responses for others
  let i = startIndex;
  while (i !== signerIndex) {
    R[i] = randomScalar();
    const commitment = G.multiply(R[i]).add(ringPoints[i].multiply(C[i]));
    const nextIndex = (i + 1) % ringSize;
    C[nextIndex] = hashToScalar(message, ringPubKeysHex, commitment);
    i = nextIndex;
  }

  // Now compute R[signer] = alpha - C[signer]*x mod N
  R[signerIndex] = mod(alpha - C[signerIndex] * x, N);

  // Format as hex
  return {
    c0: C[0].toString(16).padStart(64, "0"),
    s: R.map((r) => r.toString(16).padStart(64, "0")),
  };
}

/**
 * Verify an LSAG ring signature:
 * - `signature`: { c0, s[] } with 64-hex strings
 * - `message`: message (string or bytes)
 * - `ringPubKeysHex`: each standard SEC key (66 or 130 hex)
 *
 * Returns true or false.
 */
export function verify(
  signature: RingSignature,
  message: string | Uint8Array,
  ringPubKeysHex: string[]
): boolean {
  try {
    // Basic shape checks
    const { c0, s } = signature;
    if (!c0 || !s || s.length !== ringPubKeysHex.length) {
      return false;
    }
    const ringSize = ringPubKeysHex.length;
    if (ringSize < 1) {
      return false;
    }

    // Convert c0, s[] => BigInt
    let c = hexToBigInt(c0);
    const R = s.map(hexToBigInt);

    // Convert ring pubkeys => points
    const ringPoints = ringPubKeysHex.map(hexToPoint);

    // Recompute c in a loop
    for (let i = 0; i < ringSize; i++) {
      const Xi = G.multiply(R[i]).add(ringPoints[i].multiply(c));
      c = hashToScalar(message, ringPubKeysHex, Xi);
    }

    // Check final c == c0
    const c0Val = hexToBigInt(c0);
    return c === c0Val;
  } catch (err) {
    console.error("verify() error:", err);
    return false;
  }
}

/**
 * Generate a random scalar in [1, n-1].
 */
function randomScalar(): bigint {
  let scalar: bigint;
  do {
    const priv = secp.utils.randomPrivateKey(); // 32 random bytes
    scalar = BigInt("0x" + bytesToHex(priv));
  } while (scalar === 0n || scalar >= N);
  return scalar;
}
