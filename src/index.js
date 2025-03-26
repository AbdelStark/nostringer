import { ProjectivePoint, utils } from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

// The CURVE N value for secp256k1
const CURVE_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
);

/**
 * Parse a 64-character hex string as an x-only public key
 */
function parseXOnlyPubKey(pubKeyHex) {
  if (typeof pubKeyHex !== "string" || !/^[0-9A-Fa-f]{64}$/.test(pubKeyHex)) {
    throw new Error(
      `Invalid public key format: expected 64 hex chars, got "${pubKeyHex}"`,
    );
  }

  try {
    // In secp256k1 v2, we need to use compressed format (02 + x-coordinate)
    const compressedHex = "02" + pubKeyHex;
    return ProjectivePoint.fromHex(compressedHex);
  } catch (err) {
    throw new Error(
      `Invalid secp256k1 public key (not on curve): ${pubKeyHex}`,
    );
  }
}

/**
 * Hash a message and point for the ring signature scheme
 */
function ringHash(messageHash, point, n) {
  // Get point in compressed format
  const pointBytes = point.toRawBytes(true);

  // Combine message hash and point
  const data = new Uint8Array(messageHash.length + pointBytes.length);
  data.set(messageHash);
  data.set(pointBytes, messageHash.length);

  // Hash the combined data and return as bigint mod n
  const hash = keccak_256(data);
  return BigInt("0x" + bytesToHex(hash)) % n;
}

/**
 * Create a ring signature for a message using the provided private key and ring of public keys
 */
export function sign(message, privateKeyHex, publicKeysHex) {
  // 1. Validate inputs
  let msgBytes;
  if (typeof message === "string") {
    msgBytes = new TextEncoder().encode(message);
  } else if (message instanceof Uint8Array) {
    msgBytes = message;
  } else {
    throw new Error("Message must be a string or Uint8Array");
  }

  // Validate private key format
  if (!/^[0-9A-Fa-f]{64}$/.test(privateKeyHex)) {
    throw new Error("Private key must be 32-byte hex (64 hex chars)");
  }

  // Validate ring
  const ring = [...publicKeysHex];

  // Validate public key format first
  for (const pkHex of ring) {
    if (typeof pkHex !== "string" || !/^[0-9A-Fa-f]{64}$/.test(pkHex)) {
      throw new Error("Invalid public key format: expected 64 hex chars");
    }
  }

  // Then check ring size
  if (ring.length < 2) {
    throw new Error("Ring must have at least 2 participants for anonymity");
  }

  // 2. Get signer's public key
  const privateBytes = hexToBytes(privateKeyHex);
  const privateScalar = BigInt("0x" + privateKeyHex);
  const pubKey = ProjectivePoint.fromPrivateKey(privateBytes);
  const pubKeyHex = pubKey.x.toString(16).padStart(64, "0");

  // 3. Find signer in the ring
  const signerIndex = ring.findIndex(
    (pk) => pk.toLowerCase() === pubKeyHex.toLowerCase(),
  );
  if (signerIndex === -1) {
    throw new Error("Ring must include the signer's public key");
  }

  // 4. Parse all pubkeys to points
  const ringPoints = [];
  for (const pkHex of ring) {
    try {
      ringPoints.push(parseXOnlyPubKey(pkHex));
    } catch (err) {
      throw new Error("Invalid public key format: " + err.message);
    }
  }

  // 5. Create ring signature
  const n = CURVE_N;
  const ringSize = ring.length;

  // 5.1 Get message hash
  const msgHash = keccak_256(msgBytes);

  // 5.2 Generate random alpha scalar
  const randomBytes = utils.randomPrivateKey();
  const alpha = BigInt("0x" + bytesToHex(randomBytes)) % n;

  // 5.3 Compute signer's commitment
  const L_signer = ProjectivePoint.BASE.multiply(alpha);

  // 5.4 Initialize signature values
  const sValues = new Array(ringSize);

  // 5.5 Get initial challenge from signer's commitment
  let cNext = ringHash(msgHash, L_signer, n);
  let c0 = signerIndex === ringSize - 1 ? cNext : undefined;

  // 5.6 Forward through the ring
  for (let k = 1; k < ringSize; k++) {
    const i = (signerIndex + k) % ringSize;

    // Generate random s value
    const s_i = BigInt("0x" + bytesToHex(utils.randomPrivateKey())) % n;
    sValues[i] = s_i.toString(16).padStart(64, "0");

    // Compute Li = s_i*G + c_i*P_i
    const L_i = ProjectivePoint.BASE.multiply(s_i).add(
      ringPoints[i].multiply(cNext),
    );

    // Get next challenge
    cNext = ringHash(msgHash, L_i, n);

    // If this is the last member, save as c0
    if (i === ringSize - 1) {
      c0 = cNext;
    }
  }

  // 5.7 Compute signer's s value to close the ring
  let s_signer = (alpha - cNext * privateScalar) % n;
  if (s_signer < 0n) s_signer += n; // Ensure positive value
  sValues[signerIndex] = s_signer.toString(16).padStart(64, "0");

  // 5.8 Final c0 handling
  if (c0 === undefined) {
    c0 = cNext;
  }

  // 5.9 Return signature
  return {
    c0: c0.toString(16).padStart(64, "0"),
    s: sValues,
  };
}

/**
 * Verify a ring signature for a message against a ring of public keys
 */
export function verify(signature, message, publicKeysHex) {
  // 1. Basic validation
  if (
    !signature ||
    typeof signature.c0 !== "string" ||
    !Array.isArray(signature.s)
  ) {
    return false;
  }

  const ringSize = publicKeysHex.length;
  if (signature.s.length !== ringSize) {
    return false;
  }

  if (!/^[0-9A-Fa-f]{64}$/.test(signature.c0)) {
    return false;
  }

  // 2. Process message
  let msgBytes;
  if (typeof message === "string") {
    msgBytes = new TextEncoder().encode(message);
  } else if (message instanceof Uint8Array) {
    msgBytes = message;
  } else {
    return false;
  }

  // 3. Get message hash (same as in sign)
  const msgHash = keccak_256(msgBytes);

  // 4. Parse public keys
  const ringPoints = [];
  try {
    for (const pkHex of publicKeysHex) {
      ringPoints.push(parseXOnlyPubKey(pkHex));
    }
  } catch (err) {
    return false;
  }

  // 5. Verify signature
  const n = CURVE_N;

  // 5.1 Parse initial challenge
  let c = BigInt("0x" + signature.c0) % n;

  // 5.2 Loop through the ring
  for (let i = 0; i < ringSize; i++) {
    // Validate s value format
    const sHex = signature.s[i];
    if (!/^[0-9A-Fa-f]{64}$/.test(sHex)) {
      return false;
    }

    // Parse s value
    const s_i = BigInt("0x" + sHex) % n;

    // Compute L_i = s_i*G + c*P_i
    const L_i = ProjectivePoint.BASE.multiply(s_i).add(
      ringPoints[i].multiply(c),
    );

    // Update challenge for next iteration
    c = ringHash(msgHash, L_i, n);
  }

  // 5.3 Verify the ring closes
  const initialC = signature.c0.toLowerCase();
  const finalC = c.toString(16).padStart(64, "0").toLowerCase();

  return initialC === finalC;
}

// Helper functions removed since they are now inlined for clarity
