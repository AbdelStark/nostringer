import * as secp from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

function parseXOnlyPubKey(pubKeyHex) {
  if (typeof pubKeyHex !== "string" || !/^[0-9A-Fa-f]{64}$/.test(pubKeyHex)) {
    throw new Error(
      `Invalid public key format: expected 64 hex chars, got "${pubKeyHex}"`,
    );
  }
  const compressedHex = "02" + pubKeyHex;
  let point;
  try {
    point = secp.ProjectivePoint.fromHex(compressedHex);
  } catch (err) {
    throw new Error(
      `Invalid secp256k1 public key (not on curve): ${pubKeyHex}`,
    );
  }
  return point;
}

export function sign(message, privateKeyHex, publicKeysHex) {
  let msgBytes;
  if (typeof message === "string") {
    msgBytes = new TextEncoder().encode(message);
  } else if (message instanceof Uint8Array) {
    msgBytes = message;
  } else {
    throw new Error("Message must be a string or Uint8Array");
  }

  if (!/^[0-9A-Fa-f]{64}$/.test(privateKeyHex)) {
    throw new Error("Private key must be 32-byte hex (64 hex chars)");
  }
  const privBigInt = BigInt("0x" + privateKeyHex);
  const n = secp.CURVE.n;
  if (privBigInt === 0n || privBigInt >= n) {
    throw new Error("Invalid private key (zero or out of range)");
  }

  // Convert private key to buffer
  const privKeyBytes = hexToBytes(privateKeyHex);
  // Get public key as x-only format
  const fullPubKey = secp.getPublicKey(privKeyBytes, false);
  // Extract the x coordinate (first byte is format, then 32 bytes for x)
  const signerPubHex = bytesToHex(fullPubKey.slice(1, 33));

  const ring = [...publicKeysHex];
  const signerIndex = ring.findIndex(
    (pk) => pk.toLowerCase() === signerPubHex.toLowerCase(),
  );
  if (signerIndex === -1) {
    throw new Error("Ring must include the signer's public key");
  }

  const ringPoints = ring.map(parseXOnlyPubKey);
  const ringSize = ringPoints.length;
  if (ringSize < 2) {
    throw new Error("Ring must have at least 2 participants for anonymity");
  }

  let alpha = modRandom(n);
  if (alpha === 0n) {
    alpha = 1n;
  }
  const L_signer = secp.ProjectivePoint.BASE.multiply(alpha);

  const prefixHash = keccak_256(msgBytes);
  function ringHash(point) {
    const data = new Uint8Array(prefixHash.length + 33);
    data.set(prefixHash);
    data.set(point.toRawBytes(true), prefixHash.length);
    const digest = keccak_256(data);
    return modBigInt(digest, n);
  }

  const sVals = new Array(ringSize);

  let cNext = ringHash(L_signer);
  let c0val = signerIndex === ringSize - 1 ? cNext : undefined;

  for (let k = 1; k < ringSize; k++) {
    const i = (signerIndex + k) % ringSize;
    let s_i = modRandom(n);
    sVals[i] = s_i.toString(16).padStart(64, "0");
    const L_i = secp.ProjectivePoint.BASE.multiply(s_i).add(
      ringPoints[i].multiply(cNext),
    );
    cNext = ringHash(L_i);
    if (i === ringSize - 1) {
      c0val = cNext;
    }
  }

  const c_signer = cNext;
  const s_signer = modN(alpha - c_signer * privBigInt, n);
  sVals[signerIndex] = s_signer.toString(16).padStart(64, "0");

  if (typeof c0val === "undefined") {
    c0val = cNext;
  }

  return {
    c0: c0val.toString(16).padStart(64, "0"),
    s: sVals,
  };
}

export function verify(signature, message, publicKeysHex) {
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

  let msgBytes;
  if (typeof message === "string") {
    msgBytes = new TextEncoder().encode(message);
  } else if (message instanceof Uint8Array) {
    msgBytes = message;
  } else {
    return false;
  }

  const ringPoints = [];
  try {
    for (const pkHex of publicKeysHex) {
      ringPoints.push(parseXOnlyPubKey(pkHex));
    }
  } catch (err) {
    return false;
  }

  const n = secp.CURVE.n;
  if (!/^[0-9A-Fa-f]{64}$/.test(signature.c0)) {
    return false;
  }
  let c = BigInt("0x" + signature.c0) % n;

  const prefixHash = keccak_256(msgBytes);

  function ringHash(point) {
    const data = new Uint8Array(prefixHash.length + 33);
    data.set(prefixHash);
    data.set(point.toRawBytes(true), prefixHash.length);
    const digest = keccak_256(data);
    return modBigInt(digest, n);
  }

  for (let i = 0; i < ringSize; i++) {
    const sHex = signature.s[i];
    if (!/^[0-9A-Fa-f]{64}$/.test(sHex)) {
      return false;
    }
    const s_i = BigInt("0x" + sHex) % n;
    const Li = secp.ProjectivePoint.BASE.multiply(s_i).add(
      ringPoints[i].multiply(c),
    );
    c = ringHash(Li);
  }

  const finalC = c.toString(16).padStart(64, "0").toLowerCase();
  if (finalC !== signature.c0.toLowerCase()) {
    return false;
  }
  return true;
}

function modRandom(n) {
  let r = BigInt("0x" + bytesToHex(secp.utils.randomPrivateKey()));
  return r % n;
}

function modN(a, n) {
  const ret = a % n;
  return ret >= 0n ? ret : ret + n;
}

function modBigInt(bytes, n) {
  const val = BigInt("0x" + bytesToHex(bytes));
  return val % n;
}
