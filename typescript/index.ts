import { hkdfSync, type BinaryLike } from "crypto";
import { hex } from "@scure/base";

// Domain separation labels for HKDF to ensure different contexts produce different keys
export const INFO_INITIAL = new Uint8Array(Buffer.from("signature-key-initial", "utf8"));
export const INFO_TIMELOCK = new Uint8Array(Buffer.from("signature-key-timelock", "utf8"));

// Key derivation parameters
export const KEY_LENGTH = 32; // Output key size in bytes (256 bits)
export const CHAIN_ID_BYTES = 32; // Chain ID encoded as 32-byte big-endian (uint256)
export const TIMELOCK_BYTES = 8; // Timelock encoded as 8-byte big-endian (uint64)
export const MIN_SIGNATURE_BYTES = 32; // Minimum signature length for security

export type DerivationOptions = {
  outputLength?: number;
  infoInitialLabel?: Uint8Array;
  infoTimelockLabel?: Uint8Array;
  chainIdWidth?: number;
  timelockWidth?: number;
};

function strip0x(s: string): string {
  const t = s.trim();
  return t.startsWith("0x") || t.startsWith("0X") ? t.slice(2) : t;
}

/**
 * Strict hex parsing using @scure/base.
 * - Requires non-empty
 * - Requires even length
 * - Accepts optional 0x prefix
 */
export function hexToBytesStrict(input: string): Uint8Array {
  const clean = strip0x(input);
  if (clean.length === 0) throw new Error("Hex string cannot be empty");
  if (clean.length % 2 !== 0) throw new Error(`Hex string must have even length, got ${clean.length}`);
  try {
    return hex.decode(clean);
  } catch (e) {
    throw new Error(`Invalid hex string: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * Converts BinaryLike or hex string to bytes.
 * For strings: interpreted as hex (0x prefix allowed).
 */
export function toBytes(input: BinaryLike | string): Uint8Array {
  if (typeof input === "string") return hexToBytesStrict(input);
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  // Remaining type: Buffer. Convert safely via Buffer.from()
  if (Buffer.isBuffer(input)) {
    return new Uint8Array(input);
  }
  // Fallback for any unexpected types
  return new Uint8Array(Buffer.from(input as any));
}

/**
 * Converts bytes to 0x-prefixed hex string using @scure/base.
 */
export function bytesToHex0x(bytes: Uint8Array): string {
  return "0x" + hex.encode(bytes);
}

function assertPositiveInt(n: number, name: string) {
  if (!Number.isInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer`);
}

function assertMinLength(bytes: Uint8Array, min: number, name: string) {
  if (bytes.length < min) throw new Error(`${name} must be at least ${min} bytes, got ${bytes.length}`);
}

function assertExactLength(bytes: Uint8Array, len: number, name: string) {
  if (bytes.length !== len) throw new Error(`${name} must be exactly ${len} bytes, got ${bytes.length}`);
}

/**
 * Generic fixed-width big-endian unsigned integer encoding.
 * Only validates non-negativity and fit into `width` bytes.
 */
export function uintToFixedBE(value: bigint, width: number, name: string): Uint8Array {
  if (value < 0n) throw new Error(`${name} cannot be negative`);
  const out = new Uint8Array(width);
  let v = value;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`${name} does not fit in ${width} bytes`);
  return out;
}

/**
 * Parses chainId strictly as numeric: decimal or 0x-hex.
 * Rejects any other format.
 */
export function parseNumericId(id: string | number | bigint, name: string): bigint {
  if (typeof id === "bigint") return id;

  if (typeof id === "number") {
    if (!Number.isFinite(id) || !Number.isInteger(id) || id < 0) {
      throw new Error(`${name} must be a non-negative integer`);
    }
    return BigInt(id);
  }

  const s = id.trim();
  if (s.length === 0) throw new Error(`${name} cannot be empty`);

  // Allow "0x..." hex or decimal digits only
  if (s.startsWith("0x") || s.startsWith("0X")) {
    const hexPart = s.slice(2);
    if (hexPart.length === 0) throw new Error(`${name} hex cannot be empty`);
    // BigInt will throw if invalid
    const v = BigInt(s);
    if (v < 0n) throw new Error(`${name} must be non-negative`);
    return v;
  }

  if (!/^\d+$/.test(s)) {
    throw new Error(`${name} must be numeric (decimal or 0x hex)`);
  }
  const v = BigInt(s);
  if (v < 0n) throw new Error(`${name} must be non-negative`);
  return v;
}

/**
 * Encodes numeric chain ID as fixed-width big-endian.
 */
export function encodeChainId(chainId: string | number | bigint, width: number = CHAIN_ID_BYTES): Uint8Array {
  assertPositiveInt(width, "chainIdWidth");
  const v = parseNumericId(chainId, "chainId");
  return uintToFixedBE(v, width, "chainId");
}

/**
 * Encodes timelock as fixed-width big-endian uint64 by default.
 * Accepts decimal, 0x-hex, number, bigint. Rejects non-integer numbers and unsafe big numbers.
 */
export function encodeTimelock(timelock: bigint | number | string, width: number = TIMELOCK_BYTES): Uint8Array {
  assertPositiveInt(width, "timelockWidth");

  let v: bigint;
  if (typeof timelock === "bigint") {
    v = timelock;
  } else if (typeof timelock === "number") {
    if (!Number.isFinite(timelock) || !Number.isInteger(timelock)) throw new Error("timelock must be an integer");
    if (timelock < 0) throw new Error("timelock cannot be negative");
    if (timelock > Number.MAX_SAFE_INTEGER) throw new Error("timelock exceeds MAX_SAFE_INTEGER; pass as string or bigint");
    v = BigInt(timelock);
  } else {
    v = parseNumericId(timelock, "timelock");
  }

  // If using default uint64 width, enforce uint64 range (helps catch accidental huge values)
  if (width === 8) {
    const max = (1n << 64n) - 1n;
    if (v > max) throw new Error("timelock exceeds uint64 maximum");
  }

  return uintToFixedBE(v, width, "timelock");
}

/**
 * Creates an initial key from a signature and chain ID using HKDF.
 * - signature: opaque bytes (BinaryLike) or hex string
 * - chainId: numeric (decimal or 0x hex), number, or bigint
 * Returns: 0x-prefixed hex string representing `keyLength` bytes.
 */
export function createInitialKeyFromSignature(
  signature: BinaryLike | string,
  chainId: string | number | bigint,
  opts: DerivationOptions = {}
): string {
  const sigBytes = toBytes(signature);
  assertMinLength(sigBytes, MIN_SIGNATURE_BYTES, "signature");

  const keyLength = opts.outputLength ?? KEY_LENGTH;
  const infoInitial = opts.infoInitialLabel ?? INFO_INITIAL;
  const chainIdWidth = opts.chainIdWidth ?? CHAIN_ID_BYTES;

  assertPositiveInt(keyLength, "outputLength");
  assertPositiveInt(chainIdWidth, "chainIdWidth");

  const chainIdBytes = encodeChainId(chainId, chainIdWidth);

  const keyBuf = hkdfSync("sha256", sigBytes, chainIdBytes, infoInitial, keyLength);
  const out = new Uint8Array(keyBuf);
  assertExactLength(out, keyLength, "HKDF output");
  return bytesToHex0x(out);
}

/**
 * Derives a new key from an initial key and timelock using HKDF.
 * - initialKey must be exactly `keyLength` bytes (by default 32)
 * - timelock is encoded fixed-width (by default uint64 BE 8 bytes)
 */
export function deriveKeyFromInitialKeyAndTimelock(
  initialKey: BinaryLike | string,
  timelock: bigint | number | string,
  opts: DerivationOptions = {}
): string {
  const keyBytes = toBytes(initialKey);

  const keyLength = opts.outputLength ?? KEY_LENGTH;
  const infoTimelock = opts.infoTimelockLabel ?? INFO_TIMELOCK;
  const timelockWidth = opts.timelockWidth ?? TIMELOCK_BYTES;

  assertPositiveInt(keyLength, "outputLength");
  assertPositiveInt(timelockWidth, "timelockWidth");

  assertExactLength(keyBytes, keyLength, "initialKey");

  const timelockBytes = encodeTimelock(timelock, timelockWidth);

  const derivedBuf = hkdfSync("sha256", keyBytes, timelockBytes, infoTimelock, keyLength);
  const out = new Uint8Array(derivedBuf);
  assertExactLength(out, keyLength, "HKDF output");
  return bytesToHex0x(out);
}
