import { ProjectivePoint } from "@noble/secp256k1";
import * as secp from "@noble/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

////////////////////////////////////////////////////////////////////////////////
// TYPES & CONSTANTS
////////////////////////////////////////////////////////////////////////////////

/**
 * A ring signature consists of an initial challenge `c0`
 * plus a list of response scalars `s[]`.
 */
export interface RingSignature {
  c0: string; // 64‑hex
  s: string[]; // array of 64‑hex
}

/** Supported formats for generating a new public key. */
export type KeyFormat = "compressed" | "uncompressed" | "xonly";

const N = secp.CURVE.n; // Group order
const G = ProjectivePoint.BASE;

////////////////////////////////////////////////////////////////////////////////
// RING SIGNATURE
////////////////////////////////////////////////////////////////////////////////

/**
 * Sign a message using a SAG ring signature approach:
 *  - `message`: the data being signed
 *  - `privateKeyHex`: 64-hex (32 bytes)
 *  - `ringPubKeysHex`: each can be x-only (64-hex), compressed (66-hex), or uncompressed (130-hex).
 *
 * Returns { c0, s[] } with each scalar in 64‑hex.
 */
export function sign(
  message: string | Uint8Array,
  privateKeyHex: string,
  ringPubKeysHex: string[],
): RingSignature {
  // Parse ring pubkeys => points
  const ringPoints = ringPubKeysHex.map(hexToPoint);
  const ringSize = ringPoints.length;
  if (ringSize < 2) {
    throw new Error("Ring must have >= 2 members");
  }

  // Convert private key => normal point, then see if ring includes it
  const privNorm = normalizeHex(privateKeyHex);
  if (privNorm.length !== 64) {
    throw new Error(
      `Private key must be 64-hex (32 bytes). Got length=${privNorm.length}`,
    );
  }
  // The "unflipped" point from privateKey
  const d = BigInt("0x" + privNorm);
  const dBytes = hexToBytes(privNorm);
  let myPoint = ProjectivePoint.fromPrivateKey(dBytes);

  // Find signer's index by comparing the ring's points
  //    If the ring does NOT contain `myPoint`, we try flipping (N - d) => even-Y version
  let signerIndex = ringPoints.findIndex((p) => pointsEqual(p, myPoint));
  if (signerIndex < 0) {
    // try flipping
    const flipped = mod(-d, N);
    const flippedBytes = hexToBytes(flipped.toString(16).padStart(64, "0"));
    const flippedPoint = ProjectivePoint.fromPrivateKey(flippedBytes);
    signerIndex = ringPoints.findIndex((p) => pointsEqual(p, flippedPoint));
    if (signerIndex < 0) {
      throw new Error(
        "Ring does not include the signer's public key (neither normal nor flipped).",
      );
    }
    // If flipping is needed, adopt that privateKey for the math
    myPoint = flippedPoint;
  }

  // ring signature flow
  const R: bigint[] = new Array(ringSize);
  const C: bigint[] = new Array(ringSize);

  // ephemeral alpha
  const alpha = randomScalar();
  const alphaG = G.multiply(alpha);

  // first challenge c_start
  const startIndex = (signerIndex + 1) % ringSize;
  C[startIndex] = hashToScalar(message, ringPubKeysHex, alphaG);

  // fill random responses for i != signer
  let i = startIndex;
  while (i !== signerIndex) {
    R[i] = randomScalar();
    const commitment = G.multiply(R[i]).add(ringPoints[i].multiply(C[i]));
    const nextIndex = (i + 1) % ringSize;
    C[nextIndex] = hashToScalar(message, ringPubKeysHex, commitment);
    i = nextIndex;
  }

  // final response: R[signer] = alpha - c[signer]*privKey mod N
  const cSigner = C[signerIndex];
  // figure out which privateKey scalar was actually used
  let usedD = d;
  if (!pointsEqual(myPoint, ProjectivePoint.fromPrivateKey(dBytes))) {
    // means we used the flipped scalar
    usedD = mod(-d, N);
  }
  R[signerIndex] = mod(alpha - cSigner * usedD, N);

  return {
    c0: C[0].toString(16).padStart(64, "0"),
    s: R.map((ri) => ri.toString(16).padStart(64, "0")),
  };
}

/**
 * Verify a SAG ring signature:
 *  - `signature` = { c0, s[] }, each 64‑hex
 *  - `message`
 *  - `ringPubKeysHex`: array of x-only, compressed, or uncompressed pubkeys
 */
export function verify(
  signature: RingSignature,
  message: string | Uint8Array,
  ringPubKeysHex: string[],
): boolean {
  try {
    const { c0, s } = signature;
    if (!c0 || !s || s.length !== ringPubKeysHex.length) {
      return false;
    }
    const ringSize = ringPubKeysHex.length;
    if (ringSize < 1) return false;

    // parse ring => points
    const ringPoints = ringPubKeysHex.map(hexToPoint);

    // c0 => bigInt
    let c = hexToBigInt(c0);
    // responses => bigInt
    const R = s.map(hexToBigInt);

    // iterate
    for (let i = 0; i < ringSize; i++) {
      // X_i = R[i]*G + c_i * P[i]
      const Xi = G.multiply(R[i]).add(ringPoints[i].multiply(c));
      // c_(i+1) = hashToScalar(...)
      c = hashToScalar(message, ringPubKeysHex, Xi);
    }

    // must equal initial c0
    const c0Val = hexToBigInt(c0);
    return c === c0Val;
  } catch (err) {
    console.error("verify() error:", err);
    return false;
  }
}

/**
 * Hash (message || ringPubKeys || ephemeralPoint) => scalar mod N (non-zero).
 * - ephemeralPoint is always serialized in compressed form for stable hashing.
 */
function hashToScalar(
  message: string | Uint8Array,
  ringPubKeys: string[],
  ephemeralPoint: ProjectivePoint,
): bigint {
  let msgBytes: Uint8Array;
  if (typeof message === "string") {
    msgBytes = new TextEncoder().encode(message);
  } else {
    msgBytes = message;
  }

  // Combine all
  const buffers: Uint8Array[] = [msgBytes];

  // Add each ring pubkey in exactly the hex form the user provided
  for (const pk of ringPubKeys) {
    const norm = normalizeHex(pk);
    buffers.push(hexToBytes(norm));
  }

  // Add ephemeral point in compressed form (33 bytes)
  const ephemeralCompressed = ephemeralPoint.toRawBytes(true);
  buffers.push(ephemeralCompressed);

  // Concatenate
  const totalLen = buffers.reduce((acc, b) => acc + b.length, 0);
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const b of buffers) {
    combined.set(b, offset);
    offset += b.length;
  }

  // sha256 => mod N
  const h = sha256(combined);
  const scalar = BigInt("0x" + bytesToHex(h)) % N;
  return scalar === 0n ? 1n : scalar;
}

////////////////////////////////////////////////////////////////////////////////
// KEY GENERATION
////////////////////////////////////////////////////////////////////////////////

/**
 * Generate a new random secp256k1 key pair in the requested format:
 *   - `"compressed"`   => 66‑hex public key (33 bytes, starts with 02/03)
 *   - `"uncompressed"` => 130‑hex public key (65 bytes, starts with 04)
 *   - `"xonly"`        => 64‑hex representing just the X coordinate (assuming even Y)
 *
 * Returns an object { privateKeyHex, publicKeyHex }.
 */
export function generateKeyPair(format: KeyFormat = "compressed"): {
  privateKeyHex: string;
  publicKeyHex: string;
} {
  // 1) Random 32-byte secret
  const privBytes = secp.utils.randomPrivateKey(); // Uint8Array(32)
  const privHex = bytesToHex(privBytes); // 64 hex

  // 2) Convert secret -> full ProjectivePoint
  let point = ProjectivePoint.fromPrivateKey(privBytes);

  // 3) Format the pubkey accordingly
  let pubHex: string;

  switch (format) {
    case "xonly":
      // For x-only, we enforce "even Y" so it matches BIP340 convention
      // If Y is odd, flip the scalar => yields the negated point with even Y
      if (point.y % 2n === 1n) {
        let d = BigInt("0x" + privHex);
        d = (N - d) % N; // flip
        const flippedBytes = hexToBytes(d.toString(16).padStart(64, "0"));
        point = ProjectivePoint.fromPrivateKey(flippedBytes);
      }
      // Now Y is guaranteed even => pubKey is 64 hex of X coordinate
      pubHex = point.x.toString(16).padStart(64, "0");
      break;

    case "uncompressed":
      // 65 bytes: 04 + X(32 bytes) + Y(32 bytes) => 130 hex
      pubHex = bytesToHex(point.toRawBytes(false));
      break;

    case "compressed":
    default:
      // 33 bytes: 02/03 + X(32 bytes)
      pubHex = bytesToHex(point.toRawBytes(true));
      break;
  }

  return { privateKeyHex: privHex, publicKeyHex: pubHex };
}

////////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

/** Basic mod to ensure result is in [0, N-1]. */
function mod(a: bigint, m: bigint = N): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/** Normalize a hex string: remove '0x' if present, lowercase, even length. */
function normalizeHex(hex: string): string {
  if (typeof hex !== "string") throw new Error("Not a string");
  if (hex.startsWith("0x") || hex.startsWith("0X")) {
    hex = hex.slice(2);
  }
  hex = hex.toLowerCase();
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`Non-hex characters found: ${hex}`);
  }
  if (hex.length % 2 === 1) {
    hex = "0" + hex; // ensure even length
  }
  if (hex.length > 130) {
    // uncompressed is 130 hex max
    throw new Error(`Hex string too long: length=${hex.length}`);
  }
  return hex;
}

/** Convert hex -> BigInt, mod N. */
function hexToBigInt(h: string): bigint {
  const norm = normalizeHex(h);
  return BigInt("0x" + norm) % N;
}

/**
 * Parse a public key that might be:
 *   - 64-hex (x-only, assume even-Y => "02 + x")
 *   - 66-hex compressed ("02"/"03" prefix)
 *   - 130-hex uncompressed ("04" prefix)
 * Throws if the format is unrecognized or invalid on-curve.
 */
function hexToPoint(pubHex: string): ProjectivePoint {
  const hex = normalizeHex(pubHex);

  // x-only?
  if (hex.length === 64) {
    // x-only => even Y => "02" + x
    const candidate = "02" + hex;
    const p = ProjectivePoint.fromHex(candidate);
    p.assertValidity();
    return p;
  }

  // compressed?
  if (hex.length === 66 && (hex.startsWith("02") || hex.startsWith("03"))) {
    const p = ProjectivePoint.fromHex(hex);
    p.assertValidity();
    return p;
  }

  // uncompressed?
  if (hex.length === 130 && hex.startsWith("04")) {
    const p = ProjectivePoint.fromHex(hex);
    p.assertValidity();
    return p;
  }

  throw new Error(
    `Invalid pubkey format: length=${hex.length}, prefix=${hex.slice(0, 2)}`,
  );
}

/** Return a random scalar in [1, n-1]. */
function randomScalar(): bigint {
  while (true) {
    const raw = secp.utils.randomPrivateKey();
    const x = BigInt("0x" + bytesToHex(raw));
    if (x !== 0n && x < N) return x;
  }
}

/** Try p.equals(q), or throw if the method doesn't exist. Noble supports equals(). */
function pointsEqual(a: ProjectivePoint, b: ProjectivePoint): boolean {
  // Noble-secp256k1's ProjectivePoint has a `.equals()` method
  return a.equals(b);
}
