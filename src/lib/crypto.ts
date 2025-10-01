import { createCanonicalString } from "../utils.js";

// --- Custom Error Handling ---
export type CryptoErrorCode =
  | "UNSUPPORTED_ENVIRONMENT"
  | "ENCRYPTION_FAILED"
  | "DECRYPTION_FAILED"
  | "INVALID_DATA"
  | "INVALID_KEY"
  | "EXPIRED";

export class CryptoError extends Error {
  public readonly code: CryptoErrorCode;
  public readonly cause?: Error;
  constructor(code: CryptoErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
    this.cause = cause;
  }
}

// --- Constants/Defaults ---
const DEFAULT_TTL_MS = 60 * 60 * 1000;
const DEFAULT_PBKDF2_ITERATIONS = 100_000;

const DEFAULT_ALGO = "AES-GCM" as const;
const DEFAULT_KEY_LEN: 128 | 256 = 256;
const DEFAULT_SALT_LEN = 16;
const DEFAULT_IV_LEN = 12;

type CipherAlgorithm = "AES-GCM";
type KdfAlgorithm = "PBKDF2" | "HKDF" | "NONE";
type HashAlg = "SHA-256" | "SHA-384" | "SHA-512";

// Header: [0x45,0x47,'E','G']? keep small: 2B magic + 1B version + 1B flags + 1B saltLen + 1B ivLen + 4B iters + 8B exp
const HEADER_MAGIC0 = 0x45; // 'E'
const HEADER_MAGIC1 = 0x47; // 'G'
const HEADER_VERSION = 1;
const HEADER_SIZE = 18;

// Frame header: 8 bytes total
const STREAM_FRAME_HEADER_SIZE = 8; // seq(4) | ctLen(4)

enum KdfId {
  PBKDF2 = 0,
  HKDF = 1,
  NONE = 2,
}
enum HashId {
  SHA256 = 0,
  SHA384 = 1,
  SHA512 = 2,
}
enum AlgoId {
  AES_GCM = 0,
}

// flags layout (1 byte):
// bits 0-1: KDF (0 PBKDF2, 1 HKDF, 2 NONE)
// bit  2  : keyLen (0 => 128, 1 => 256)
// bits 3-4: hash (0 256, 1 384, 2 512)
// bits 6-7: reserved
function packFlags(
  kdf: KdfAlgorithm,
  keyLen: 128 | 256,
  hash: HashAlg,
): number {
  const kdfBits = kdf === "PBKDF2"
    ? KdfId.PBKDF2
    : kdf === "HKDF"
    ? KdfId.HKDF
    : KdfId.NONE;
  const keyBit = keyLen === 256 ? 1 : 0;
  const hashBits = hash === "SHA-256"
    ? HashId.SHA256
    : hash === "SHA-384"
    ? HashId.SHA384
    : HashId.SHA512;
  const algoBit = AlgoId.AES_GCM; // only 0 currently
  return (kdfBits & 0b11) | ((keyBit & 1) << 2) | ((hashBits & 0b11) << 3) |
    ((algoBit & 1) << 5);
}
function unpackFlags(
  flags: number,
): {
  kdf: KdfAlgorithm;
  keyLen: 128 | 256;
  hash: HashAlg;
  algo: CipherAlgorithm;
} {
  const kdfBits = flags & 0b11;
  const keyBit = (flags >> 2) & 1;
  const hashBits = (flags >> 3) & 0b11;
  const algoBit = (flags >> 5) & 1;
  const kdf: KdfAlgorithm = kdfBits === KdfId.PBKDF2
    ? "PBKDF2"
    : kdfBits === KdfId.HKDF
    ? "HKDF"
    : "NONE";
  const keyLen: 128 | 256 = keyBit ? 256 : 128;
  const hash: HashAlg = hashBits === HashId.SHA256
    ? "SHA-256"
    : hashBits === HashId.SHA384
    ? "SHA-384"
    : "SHA-512";
  const algo: CipherAlgorithm = algoBit === AlgoId.AES_GCM
    ? "AES-GCM"
    : "AES-GCM";
  return { kdf, keyLen, hash, algo };
}

// --- Options you can pass to encryptString/encrypt (they'll be embedded) ---
/**
 * Options that control how data is encrypted and what is embedded in the token header.
 *
 * All values are self-described inside the authenticated header so the decrypt
 * side does not need to be given the same options explicitly. Defaults are shown
 * in brackets. Set only what you need to override.
 *
 * Notes
 * - ttl: When null, no expiration is enforced (stored as Infinity in the header).
 * - kdf:
 *   - "PBKDF2" is recommended for password-like secrets (CPU-hard).
 *   - "HKDF" is lighter and good for high-entropy secrets.
 *   - "NONE" treats secretKey as a raw AES key; its UTF-8 byte length must be
 *     exactly 16 bytes (AES-128) or 32 bytes (AES-256).
 * - keyLengthBits: 128 is faster; 256 is the default.
 * - ivLengthBytes: 12 (96-bit) is the NIST-recommended size for AES-GCM.
 *
 * @property {number|null} [ttl=3600000]
 *   Time-to-live in milliseconds. If set to null, the token never expires.
 *
 * @property {"AES-GCM"} [algorithm="AES-GCM"]
 *   Authenticated cipher algorithm. Only AES-GCM is currently supported.
 *
 * @property {128|256} [keyLengthBits=256]
 *   AES key length in bits. Use 128 for better performance on constrained devices.
 *
 * @property {"PBKDF2"|"HKDF"|"NONE"} [kdf="PBKDF2"]
 *   Key derivation function used to turn `secretKey` into an AES key.
 *
 * @property {number} [pbkdf2Iterations=100000]
 *   PBKDF2 iteration count (used only when kdf is "PBKDF2").
 *
 * @property {"SHA-256"|"SHA-384"|"SHA-512"} [hash="SHA-256"]
 *   Hash function used by PBKDF2/HKDF.
 *
 * @property {number} [saltLengthBytes=16]
 *   Length in bytes of the random salt (ignored when kdf is "NONE").
 *
 * @property {number} [ivLengthBytes=12]
 *   Length in bytes of the random initialization vector (IV) for AES-GCM.
 */
export interface CryptoOptions {
  ttl?: number | null;
  algorithm?: CipherAlgorithm; // default AES-GCM
  keyLengthBits?: 128 | 256; // 128 is faster
  kdf?: KdfAlgorithm; // PBKDF2 | HKDF | NONE
  pbkdf2Iterations?: number; // for PBKDF2
  hash?: HashAlg; // for PBKDF2/HKDF
  saltLengthBytes?: number; // default 16
  ivLengthBytes?: number; // default 12 for GCM
}

// --- Utilities ---
function ensureWebCryptoAvailable(): void {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new CryptoError(
      "UNSUPPORTED_ENVIRONMENT",
      "Web Crypto API (crypto.subtle) is not available in this environment.",
    );
  }
}

function encUtf8(s: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(s);
}
function decUtf8(bytes: BufferSource): string {
  const u8 = toU8(bytes);
  return new TextDecoder().decode(u8);
}

function base64ToUint8Array(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function arrayToBase64(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let s = "";
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk) as any);
  }
  return btoa(s);
}
function toBase64Url(bytes: Uint8Array): string {
  return arrayToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(
    /=+$/g,
    "",
  );
}
function fromBase64Url(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) & 3;
  if (pad) b64 += "=".repeat(pad);
  return base64ToUint8Array(b64);
}

function decodeTokenToBytes(encryptedData: string): Uint8Array {
  // Try base64url first; fall back to standard base64 for legacy tokens
  try {
    return fromBase64Url(encryptedData);
  } catch (error: any) {
    try {
      return base64ToUint8Array(encryptedData);
    } catch {
      throw new CryptoError(
        "INVALID_DATA",
        "Invalid encrypted data: base64 decode failed.",
        error,
      );
    }
  }
}

function toU8(input: BufferSource): Uint8Array<ArrayBuffer> {
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    const view = input as ArrayBufferView;
    return new Uint8Array(
      view.buffer,
      view.byteOffset,
      view.byteLength,
    ) as Uint8Array<ArrayBuffer>;
  }
  throw new CryptoError("INVALID_DATA", "Expected BufferSource.");
}

// --- KDFs ---
async function importRawAesKey(
  raw: ArrayBufferView,
  algorithm: CipherAlgorithm,
  keyLengthBits: 128 | 256,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  if (raw.byteLength !== keyLengthBits / 8) {
    throw new CryptoError(
      "INVALID_KEY",
      `Raw key must be ${keyLengthBits / 8} bytes (got ${raw.byteLength}).`,
    );
  }
  return crypto.subtle.importKey(
    "raw",
    raw as BufferSource,
    { name: algorithm, length: keyLengthBits },
    false,
    usage,
  );
}

async function deriveKeyForEncrypt(
  secretKey: string,
  salt: Uint8Array,
  usage: KeyUsage[],
  kdf: KdfAlgorithm,
  hash: HashAlg,
  pbkdf2Iterations: number,
  algorithm: CipherAlgorithm,
  keyLengthBits: 128 | 256,
): Promise<CryptoKey> {
  if (kdf === "NONE") {
    // Use secret bytes directly as AES key (must be 16/32 bytes when UTF-8 encoded)
    const keyBytes = encUtf8(secretKey);
    return importRawAesKey(keyBytes, algorithm, keyLengthBits, usage);
  }
  if (kdf === "PBKDF2") {
    const pw = await crypto.subtle.importKey(
      "raw",
      encUtf8(secretKey) as BufferSource,
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: pbkdf2Iterations,
        hash,
      },
      pw,
      { name: algorithm, length: keyLengthBits },
      false,
      usage,
    );
  }
  // HKDF
  const ikm = await crypto.subtle.importKey(
    "raw",
    encUtf8(secretKey) as BufferSource,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt: salt as BufferSource, info: new Uint8Array(), hash },
    ikm,
    { name: algorithm, length: keyLengthBits },
    false,
    usage,
  );
}

// --- Header build/parse ---
function buildHeader(
  kdf: KdfAlgorithm,
  keyLen: 128 | 256,
  hash: HashAlg,
  saltLen: number,
  ivLen: number,
  pbkdf2Iterations: number,
  expirationTimestamp: number,
): Uint8Array {
  const hdr = new Uint8Array(HEADER_SIZE);
  hdr[0] = HEADER_MAGIC0;
  hdr[1] = HEADER_MAGIC1;
  hdr[2] = HEADER_VERSION;
  hdr[3] = packFlags(kdf, keyLen, hash);
  hdr[4] = saltLen & 0xff;
  hdr[5] = ivLen & 0xff;
  // iters (uint32, big-endian)
  const dv = new DataView(hdr.buffer, hdr.byteOffset);
  dv.setUint32(6, pbkdf2Iterations >>> 0, false);
  // expiration (float64, big-endian)
  dv.setFloat64(10, expirationTimestamp, false);
  return hdr;
}

function parseHeader(buf: Uint8Array): {
  kdf: KdfAlgorithm;
  keyLen: 128 | 256;
  hash: HashAlg;
  algo: CipherAlgorithm;
  saltLen: number;
  ivLen: number;
  pbkdf2Iterations: number;
  expiration: number;
} {
  if (buf.length < HEADER_SIZE) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: header too short.",
    );
  }
  if (
    buf[0] !== HEADER_MAGIC0 || buf[1] !== HEADER_MAGIC1 ||
    buf[2] !== HEADER_VERSION
  ) {
    throw new CryptoError("INVALID_DATA", "Invalid header magic/version.");
  }
  const { kdf, keyLen, hash, algo } = unpackFlags(buf[3]);
  const saltLen = buf[4];
  const ivLen = buf[5];
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const pbkdf2Iterations = dv.getUint32(6, false);
  const expiration = dv.getFloat64(10, false);
  return {
    kdf,
    keyLen,
    hash,
    algo,
    saltLen,
    ivLen,
    pbkdf2Iterations,
    expiration,
  };
}

// --- Core, shared between string and raw APIs ---

function hasNewHeader(bytes: Uint8Array): boolean {
  return bytes.length >= HEADER_SIZE &&
    bytes[0] === HEADER_MAGIC0 &&
    bytes[1] === HEADER_MAGIC1 &&
    bytes[2] === HEADER_VERSION;
}

/**
 * Core encrypt routine. Returns raw bytes: [header | salt | iv | ciphertext]
 */
async function encryptCore(
  data: BufferSource,
  secretKey: string,
  options: CryptoOptions,
): Promise<Uint8Array<ArrayBuffer>> {
  const {
    ttl = DEFAULT_TTL_MS,
    algorithm = DEFAULT_ALGO,
    keyLengthBits = DEFAULT_KEY_LEN,
    kdf = "PBKDF2",
    pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS,
    hash = "SHA-256",
    saltLengthBytes = DEFAULT_SALT_LEN,
    ivLengthBytes = DEFAULT_IV_LEN,
  } = options;

  const expiration = ttl === null ? Infinity : Date.now() + ttl;
  const salt = kdf === "NONE"
    ? new Uint8Array(0)
    : crypto.getRandomValues(new Uint8Array(saltLengthBytes));
  const iv = crypto.getRandomValues(new Uint8Array(ivLengthBytes));

  const header = buildHeader(
    kdf,
    keyLengthBits,
    hash,
    salt.length,
    iv.length,
    kdf === "PBKDF2" ? pbkdf2Iterations : 0,
    expiration,
  );

  // Derive/import key
  const key = await deriveKeyForEncrypt(
    secretKey,
    salt,
    ["encrypt"],
    kdf,
    hash,
    pbkdf2Iterations,
    algorithm,
    keyLengthBits,
  );

  // Encrypt with header as AAD (authenticates embedded options)
  const ciphertext = await crypto.subtle.encrypt(
    { name: algorithm, iv, additionalData: header as BufferSource },
    key,
    data,
  );

  // Compose: [header | salt | iv | ciphertext]
  const ct = new Uint8Array(ciphertext);
  const out = new Uint8Array(
    header.length + salt.length + iv.length + ct.length,
  );
  let off = 0;
  out.set(header, off);
  off += header.length;
  out.set(salt, off);
  off += salt.length;
  out.set(iv, off);
  off += iv.length;
  out.set(ct, off);
  return out;
}

/**
 * Core decrypt routine. Accepts raw bytes (headered or legacy), returns plaintext bytes.
 */
async function decryptCore(
  bytes: Uint8Array,
  secretKey: string,
): Promise<Uint8Array<ArrayBuffer>> {
  // Detect header magic; fall back to legacy if absent
  if (!hasNewHeader(bytes)) {
    // Legacy layout: [iters(4)|exp(8)|salt(16)|iv(12)|ciphertext], AES-256-GCM, PBKDF2/SHA-256
    const ITERATIONS_LENGTH_BYTES = 4;
    const EXPIRATION_LENGTH_BYTES = 8;
    const SALT_LENGTH_BYTES = 16;
    const IV_LENGTH_BYTES = 12;
    const minLen = ITERATIONS_LENGTH_BYTES + EXPIRATION_LENGTH_BYTES +
      SALT_LENGTH_BYTES + IV_LENGTH_BYTES + 1;
    if (bytes.length < minLen) {
      throw new CryptoError(
        "INVALID_DATA",
        "Invalid encrypted data: payload is too short.",
      );
    }

    let offset = 0;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const iters = dv.getUint32(offset, false);
    offset += ITERATIONS_LENGTH_BYTES;
    const expiration = dv.getFloat64(offset, false);
    offset += EXPIRATION_LENGTH_BYTES;
    if (Date.now() > expiration) {
      throw new CryptoError("EXPIRED", "The encrypted data has expired.");
    }
    const salt = bytes.subarray(offset, offset + SALT_LENGTH_BYTES);
    offset += SALT_LENGTH_BYTES;
    const iv = bytes.subarray(offset, offset + IV_LENGTH_BYTES);
    offset += IV_LENGTH_BYTES;
    const ciphertext = bytes.subarray(offset);

    const key = await deriveKeyForEncrypt(
      secretKey,
      salt,
      ["decrypt"],
      "PBKDF2",
      "SHA-256",
      iters,
      "AES-GCM",
      256,
    );

    try {
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as BufferSource },
        key,
        ciphertext as BufferSource,
      );
      return new Uint8Array(pt);
    } catch (error: any) {
      throw new CryptoError(
        "DECRYPTION_FAILED",
        "Decryption failed. Wrong key or tampered data.",
        error,
      );
    }
  }

  // New headered format
  const header = parseHeader(bytes.subarray(0, HEADER_SIZE));
  const {
    kdf,
    keyLen,
    hash,
    algo,
    saltLen,
    ivLen,
    pbkdf2Iterations,
    expiration,
  } = header;

  if (Date.now() > expiration) {
    throw new CryptoError("EXPIRED", "The encrypted data has expired.");
  }

  const minLen = HEADER_SIZE + saltLen + ivLen + 1;
  if (bytes.length < minLen) {
    throw new CryptoError(
      "INVALID_DATA",
      "Invalid encrypted data: truncated payload.",
    );
  }

  let offset = HEADER_SIZE;
  const salt = bytes.subarray(offset, offset + saltLen);
  offset += saltLen;
  const iv = bytes.subarray(offset, offset + ivLen);
  offset += ivLen;
  const ciphertext = bytes.subarray(offset);

  // Derive/import key using embedded options
  const key = await deriveKeyForEncrypt(
    secretKey,
    salt,
    ["decrypt"],
    kdf,
    hash,
    pbkdf2Iterations,
    algo,
    keyLen,
  );

  try {
    const pt = await crypto.subtle.decrypt(
      {
        name: algo,
        iv: iv as BufferSource,
        additionalData: bytes.subarray(0, HEADER_SIZE) as BufferSource,
      },
      key,
      ciphertext as BufferSource,
    );
    return new Uint8Array(pt);
  } catch (error: any) {
    throw new CryptoError(
      "DECRYPTION_FAILED",
      "Decryption failed. Wrong key or tampered data.",
      error,
    );
  }
}

// --- Public API ---

/**
 * Encrypts raw binary data with the same headered token format used by encryptString.
 *
 * The header is supplied as AES-GCM AAD to authenticate parameters.
 *
 * @async
 * @function encrypt
 * @param {string} data
 *   The raw binary to encrypt.
 * @param {string} secretKey
 *   The secret used for key derivation or as the raw AES key depending on `options.kdf`.
 *     - If `options.kdf` is "PBKDF2" or "HKDF", this may be any string (e.g., a password or high-entropy secret).
 *     - If `options.kdf` is "NONE", the UTF-8 byte length of `secretKey` must match the AES key size: 16 bytes for AES-128 or 32 bytes for AES-256.
 * @param {Object} [options] Optional encryption parameters to embed in the output. Decrypt will auto-discover these from the header.
 *
 * @returns {Promise<Uint8Array>}
 *   A Uint8Array containing the authenticated header, salt, IV, and ciphertext; [header | salt | iv | ciphertext].
 * @throws {CryptoError}
 *   - code: "UNSUPPORTED_ENVIRONMENT" when Web Crypto (`crypto.subtle`) is unavailable.
 *   - code: "ENCRYPTION_FAILED" for any failure during key derivation, parameter validation, or encryption.
 */
export async function encrypt(
  data: BufferSource,
  secretKey: string,
  options: CryptoOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
  ensureWebCryptoAvailable();
  try {
    return await encryptCore(toU8(data), secretKey, options);
  } catch (error: any) {
    throw new CryptoError(
      "ENCRYPTION_FAILED",
      `Encryption failed: ${error.message}`,
      error,
    );
  }
}

/**
 * Decrypts raw bytes produced by `encrypt` (or the string variant after base64 decode), enforcing TTL.
 * Accepts either the new headered format or the legacy headerless layout.
 *
 * No options needed; everything is embedded in the encrypted data.
 *
 * @param encryptedData The Base64 encoded string from encryptString.
 * @param secretKey The *same* secret key used for encryption.
 * @returns A Promise resolving to the original plaintext string.
 * @throws {CryptoError}
 */
export async function decrypt(
  encryptedBytes: BufferSource,
  secretKey: string,
): Promise<Uint8Array<ArrayBuffer>> {
  ensureWebCryptoAvailable();
  const bytes = toU8(encryptedBytes);
  return decryptCore(bytes, secretKey);
}

/**
 * Encrypts a plaintext string with AES-GCM and embeds all necessary decryption
 * parameters (KDF, key length, hash, salt/IV sizes, iteration count, and TTL)
 * in an authenticated header inside the output token. The result is a compact,
 * base64url-encoded string that `decryptString` can decode without any options.
 *
 * Security and performance guidance
 * - Use `kdf: "PBKDF2"` for password-like secrets (default; strongest for low-entropy input).
 * - Prefer `kdf: "HKDF"` for high-entropy secrets; it is much lighter than PBKDF2.
 * - Use `kdf: "NONE"` only with a pre-shared high-entropy key whose UTF-8 bytes are
 *   exactly 16 (AES-128) or 32 (AES-256); otherwise encryption will fail.
 * - `keyLengthBits: 128` is typically faster than 256 and is acceptable for most apps.
 *
 * Encoding
 * - Returns a base64url string (URL-safe; no `=` padding). No `encodeURIComponent` is needed.
 *
 * @async
 * @function encryptString
 * @param {string} plaintext
 *   The UTF-8 string to encrypt.
 * @param {string} secretKey
 *   The secret used for key derivation or as the raw AES key depending on `options.kdf`.
 *     - If `options.kdf` is "PBKDF2" or "HKDF", this may be any string (e.g., a password or high-entropy secret).
 *     - If `options.kdf` is "NONE", the UTF-8 byte length of `secretKey` must match the AES key size: 16 bytes for AES-128 or 32 bytes for AES-256.
 * @param {Object} [options] Optional encryption parameters to embed in the token. Decrypt will auto-discover these from the header.
 *
 * @returns {Promise<string>}
 *   A base64url-encoded token containing the authenticated header, salt, IV, and ciphertext.
 * @throws {CryptoError}
 *   - code: "UNSUPPORTED_ENVIRONMENT" when Web Crypto (`crypto.subtle`) is unavailable.
 *   - code: "ENCRYPTION_FAILED" for any failure during key derivation, parameter validation, or encryption.
 *
 * @example <caption>Default settings (PBKDF2 + AES-256-GCM, 1-hour TTL)</caption>
 * const token = await encryptString("hello world", "my strong passphrase");
 *
 * @example <caption>Faster settings for high-entropy secret (HKDF + AES-128-GCM)</caption>
 * const token = await encryptString("data", secret, {
 *   kdf: "HKDF",
 *   keyLengthBits: 128,
 * });
 *
 * @example <caption>Use a pre-shared raw key (kdf: "NONE")</caption>
 * // secretKey must be exactly 32 UTF-8 bytes for AES-256 (or 16 for AES-128)
 * const token = await encryptString("data", "0123456789abcdef0123456789abcdef", {
 *   kdf: "NONE",
 *   keyLengthBits: 256
 * });
 *
 * @see encrypt — for the raw-bytes variant.
 * @see decryptString — Decrypts a token by reading the embedded header; no options required.
 */
export async function encryptString(
  plaintext: string,
  secretKey: string,
  options: CryptoOptions = {},
): Promise<string> {
  ensureWebCryptoAvailable();
  try {
    const out = await encryptCore(encUtf8(plaintext), secretKey, options);
    return toBase64Url(out);
  } catch (error: any) {
    throw new CryptoError(
      "ENCRYPTION_FAILED",
      `Encryption failed: ${error.message}`,
      error,
    );
  }
}

/**
 * Decrypts a string that was encrypted with `encryptString`, checking its TTL.
 *
 * No options needed; everything is embedded in the encrypted data.
 *
 * @param encryptedData The Base64 encoded string from encryptString.
 * @param secretKey The *same* secret key used for encryption.
 * @returns A Promise resolving to the original plaintext string.
 * @throws {CryptoError}
 */
export async function decryptString(
  encryptedData: string,
  secretKey: string,
): Promise<string> {
  ensureWebCryptoAvailable();

  const bytes = decodeTokenToBytes(encryptedData);
  const pt = await decryptCore(bytes, secretKey);
  return decUtf8(pt);
}

// --- Streaming API (Web Streams) ---

/**
 * Create a TransformStream that encrypts Uint8Array chunks into framed, AEAD-protected chunks.
 * Output begins with a single prologue [header|salt|baseIV], then frames: [seq|ctLen|ciphertext].
 */
export function encryptStream(
  secretKey: string,
  options: CryptoOptions = {},
): TransformStream<Uint8Array, Uint8Array> {
  ensureWebCryptoAvailable();

  // Prepare once in start()
  let started = false;
  let seq = 0;

  // Immutable stream parameters (decided at start)
  let header!: Uint8Array;
  let salt!: Uint8Array;
  let baseIV!: Uint8Array;
  let key!: CryptoKey;
  let algo!: CipherAlgorithm;
  let keyLengthBits!: 128 | 256;
  let kdf!: KdfAlgorithm;
  let hash!: HashAlg;
  let pbkdf2Iterations!: number;

  // AAD buffer reused across frames: header (fixed) + seq (mutating u32)
  let aad!: Uint8Array;
  let aadView!: DataView;

  async function start(
    controller: TransformStreamDefaultController<Uint8Array>,
  ) {
    const {
      ttl = DEFAULT_TTL_MS,
      algorithm = DEFAULT_ALGO,
      keyLengthBits: kBits = DEFAULT_KEY_LEN,
      kdf: kdfAlg = "PBKDF2",
      pbkdf2Iterations: iters = DEFAULT_PBKDF2_ITERATIONS,
      hash: hashAlg = "SHA-256",
      saltLengthBytes = DEFAULT_SALT_LEN,
      ivLengthBytes = DEFAULT_IV_LEN, // 12 recommended for GCM
    } = options;

    algo = algorithm;
    keyLengthBits = kBits;
    kdf = kdfAlg;
    hash = hashAlg;
    pbkdf2Iterations = kdf === "PBKDF2" ? iters : 0;

    const expiration = ttl === null ? Infinity : Date.now() + ttl;
    salt = kdf === "NONE"
      ? new Uint8Array(0)
      : crypto.getRandomValues(new Uint8Array(saltLengthBytes));

    // baseIV used to derive per-frame IVs by setting last 4 bytes to seq (big‑endian)
    baseIV = crypto.getRandomValues(new Uint8Array(ivLengthBytes));
    if (baseIV.length < 12) {
      // Require 12 bytes so we have at least 4 bytes for a counter without reducing nonce entropy too far
      throw new CryptoError(
        "INVALID_DATA",
        "ivLengthBytes must be at least 12 for streaming mode.",
      );
    }

    header = buildHeader(
      kdf,
      keyLengthBits,
      hash,
      salt.length,
      baseIV.length,
      pbkdf2Iterations,
      expiration,
    );

    key = await deriveKeyForEncrypt(
      secretKey,
      salt,
      ["encrypt"],
      kdf,
      hash,
      kdf === "PBKDF2" ? iters : 0,
      algo,
      keyLengthBits,
    );

    // Prepare AAD = header || seq(u32BE) (mutates last 4 bytes)
    aad = new Uint8Array(HEADER_SIZE + 4);
    aad.set(header, 0);
    aadView = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);

    // Emit prologue
    controller.enqueue(header);
    if (salt.length) controller.enqueue(salt);
    controller.enqueue(baseIV);

    started = true;
  }

  return new TransformStream<Uint8Array, Uint8Array>({
    start,
    async transform(chunk, controller) {
      if (!started) {
        await start(controller);
      }
      const data = toU8(chunk as Uint8Array<ArrayBuffer>);

      // Derive per-frame IV from baseIV and seq
      const iv = new Uint8Array(baseIV); // copy
      const ivView = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
      ivView.setUint32(iv.length - 4, seq >>> 0, false); // big-endian

      // AAD = header || seq
      aadView.setUint32(HEADER_SIZE, seq >>> 0, false);

      // Encrypt one frame
      let ciphertext: ArrayBuffer;
      try {
        ciphertext = await crypto.subtle.encrypt(
          {
            name: algo,
            iv: iv as BufferSource,
            additionalData: aad as BufferSource,
          },
          key,
          data as BufferSource,
        );
      } catch (error: any) {
        throw new CryptoError(
          "ENCRYPTION_FAILED",
          `Stream encryption failed at frame ${seq}: ${error.message}`,
          error,
        );
      }

      const ct = new Uint8Array(ciphertext);
      const frame = new Uint8Array(STREAM_FRAME_HEADER_SIZE + ct.length);
      const dv = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
      dv.setUint32(0, seq >>> 0, false); // seq
      dv.setUint32(4, ct.length >>> 0, false); // ctLen
      frame.set(ct, STREAM_FRAME_HEADER_SIZE);

      controller.enqueue(frame);
      seq++;
    },
  });
}

/**
 * Create a TransformStream that decrypts bytes produced by `encryptStream`.
 * Consumes: [header|salt|baseIV] once, then frames [seq|ctLen|ciphertext].
 * Produces the original plaintext chunks in order, enforcing TTL and sequence.
 */
export function decryptStream(
  secretKey: string,
): TransformStream<Uint8Array, Uint8Array> {
  ensureWebCryptoAvailable();

  // Accumulator for parsing across arbitrary chunk boundaries
  let buffer = new Uint8Array(0);

  let headerParsed = false;
  let header!: Uint8Array;
  let headerFields!: ReturnType<typeof parseHeader>;
  let baseIV!: Uint8Array;
  let key!: CryptoKey;
  let expectedSeq = 0;

  // Reusable AAD = header || seq
  let aad!: Uint8Array;
  let aadView!: DataView;

  function appendBuffer(src: Uint8Array) {
    if (src.length === 0) return;
    const out = new Uint8Array(buffer.length + src.length);
    out.set(buffer, 0);
    out.set(src, buffer.length);
    buffer = out;
  }

  function tryRead(n: number): boolean {
    return buffer.length >= n;
  }

  function consume(n: number): Uint8Array {
    const out = buffer.subarray(0, n);
    buffer = buffer.subarray(n);
    return out;
  }

  async function parsePrologue() {
    if (!tryRead(HEADER_SIZE)) return false;

    header = consume(HEADER_SIZE); // keep a copy of header bytes
    headerFields = parseHeader(header);

    const {
      saltLen,
      ivLen,
      expiration,
      kdf,
      hash,
      pbkdf2Iterations,
      algo,
      keyLen,
    } = headerFields;

    if (Date.now() > expiration) {
      throw new CryptoError("EXPIRED", "The encrypted stream has expired.");
    }

    const need = saltLen + ivLen;
    if (!tryRead(need)) {
      // put the header back in front for next time
      buffer = new Uint8Array([...header, ...buffer]);
      return false;
    }

    const salt = consume(saltLen);
    baseIV = consume(ivLen);

    key = await deriveKeyForEncrypt(
      secretKey,
      salt,
      ["decrypt"],
      kdf,
      hash,
      pbkdf2Iterations,
      algo,
      keyLen,
    );

    // Prepare AAD buffer
    aad = new Uint8Array(HEADER_SIZE + 4);
    aad.set(header, 0);
    aadView = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);

    headerParsed = true;
    return true;
  }

  async function tryDecryptFrames(
    controller: TransformStreamDefaultController<Uint8Array>,
  ) {
    // Process as many complete frames as possible
    while (true) {
      if (!tryRead(STREAM_FRAME_HEADER_SIZE)) break;

      const hdr = buffer.subarray(0, STREAM_FRAME_HEADER_SIZE);
      const dv = new DataView(
        hdr.buffer,
        hdr.byteOffset,
        STREAM_FRAME_HEADER_SIZE,
      );
      const seq = dv.getUint32(0, false);
      const ctLen = dv.getUint32(4, false);

      if (!tryRead(STREAM_FRAME_HEADER_SIZE + ctLen)) break;

      // Consume header and ciphertext
      consume(STREAM_FRAME_HEADER_SIZE);
      const ct = consume(ctLen);

      // Enforce monotonic sequence
      if (seq !== expectedSeq) {
        throw new CryptoError(
          "INVALID_DATA",
          `Out-of-order or missing frame: expected ${expectedSeq}, got ${seq}.`,
        );
      }

      // IV = baseIV with last 4 bytes set to seq
      const iv = new Uint8Array(baseIV);
      const ivView = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
      ivView.setUint32(iv.length - 4, seq >>> 0, false);

      // AAD = header || seq
      aadView.setUint32(HEADER_SIZE, seq >>> 0, false);

      try {
        const pt = await crypto.subtle.decrypt(
          {
            name: headerFields.algo,
            iv: iv as BufferSource,
            additionalData: aad as BufferSource,
          },
          key,
          ct as BufferSource,
        );
        controller.enqueue(new Uint8Array(pt));
      } catch (error: any) {
        throw new CryptoError(
          "DECRYPTION_FAILED",
          `Stream decryption failed at frame ${seq}.`,
          error,
        );
      }

      expectedSeq++;
    }
  }

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      appendBuffer(toU8(chunk as Uint8Array<ArrayBuffer>));

      if (!headerParsed) {
        // Try to parse prologue; if not enough, wait for more data
        const ok = await parsePrologue();
        if (!ok) return;
      }

      await tryDecryptFrames(controller);
    },
    async flush(controller) {
      if (!headerParsed) {
        throw new CryptoError(
          "INVALID_DATA",
          "Stream ended before header was received.",
        );
      }
      // After consuming all complete frames, leftover bytes indicate truncation
      if (buffer.length !== 0) {
        throw new CryptoError(
          "INVALID_DATA",
          "Truncated ciphertext at end of stream.",
        );
      }
    },
  });
}

/**
 * Asynchronously calculates a hash of the given data using the specified algorithm.
 *
 * This function uses the Web Crypto API's `crypto.subtle.digest` method to generate
 * a cryptographic hash. The resulting hash is returned as a hexadecimal string.
 *
 * @param {BufferSource} data The data to hash. This can be an ArrayBuffer or any ArrayBufferView (e.g., a Uint8Array).
 * @param {AlgorithmIdentifier} [algorithm="SHA-256"] The hashing algorithm to use.
 * @returns {Promise<string>} A promise that resolves to a string containing the hexadecimal representation of the hash.
 * @throws {Error} Throws an error if the hashing operation fails.
 * @example
 * const data = new TextEncoder().encode("hello world");
 * const sha256Hash = await hash(data); // uses SHA-256 by default
 * const sha512Hash = await hash(data, "SHA-512");
 */
export async function hash(
  data: BufferSource,
  algorithm: AlgorithmIdentifier = "SHA-256",
) {
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Asynchronously calculates a deterministic hash of any JavaScript object using a specified algorithm.
 *
 * This function handles complex data structures including Maps, Sets, Dates,
 * BigInts, and circular references. It creates a consistent, sorted string
 * representation of the object, ensuring that the same logical object always
 * produces the same hash, regardless of key order or environment.
 *
 * @param {any} obj The object to hash. This can be any serializable JavaScript value.
 * @param {AlgorithmIdentifier} [algorithm="SHA-256"] The hashing algorithm to use.
 * @returns {Promise<string>} A promise that resolves to a string containing the hexadecimal representation of the hash.
 * @example
 * const obj1 = { b: 2, a: { c: 3, d: new Set([1, 2]) } };
 * const hash1 = await hashObject(obj1); // SHA-256
 * const hash2 = await hashObject(obj1, "SHA-512");
 * // hash1 will be different from hash2
 */
export async function hashObject(
  obj: any,
  algorithm: AlgorithmIdentifier = "SHA-256",
): Promise<string> {
  const objectString = createCanonicalString(obj);
  const data = new TextEncoder().encode(objectString);
  return await hash(data, algorithm);
}
