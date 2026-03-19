/**
 * PHANTOM CHAT - Encryption Utilities
 *
 * Server-side encryption uses AES-256-GCM.
 * Client-side E2E encryption uses the Web Crypto API (see frontend).
 *
 * Flow:
 *   1. Client encrypts message with room shared key (E2E, AES-GCM via WebCrypto)
 *   2. Server re-encrypts ciphertext for storage (defense-in-depth)
 *   3. On retrieval, server decrypts storage layer → sends E2E ciphertext to client
 *   4. Client decrypts with shared key
 */

'use strict';

const crypto = require('crypto');

const ALGORITHM   = 'aes-256-gcm';
const KEY_LENGTH  = 32; // 256 bits
const IV_LENGTH   = 12; // 96 bits (recommended for GCM)
const TAG_LENGTH  = 16; // 128 bits

/**
 * Derive a stable AES-256 key from the ENCRYPTION_KEY env var.
 * Uses HKDF-like derivation with SHA-256.
 */
function getDerivedKey() {
  const rawKey = process.env.ENCRYPTION_KEY || 'fallback-key-change-in-production-please';
  // Derive 32 bytes from whatever key material we have
  return crypto.createHash('sha256').update(rawKey).digest();
}

/**
 * Encrypt plaintext string → { ciphertext, iv, authTag } (all base64)
 *
 * @param {string} plaintext
 * @returns {{ ciphertext: string, iv: string, authTag: string }}
 */
function encrypt(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') {
    throw new Error('encrypt: plaintext must be a non-empty string');
  }

  const key = getDerivedKey();
  const iv  = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('base64'),
    iv:         iv.toString('base64'),
    authTag:    authTag.toString('base64'),
  };
}

/**
 * Decrypt ciphertext → plaintext string
 *
 * @param {string} ciphertext - base64
 * @param {string} iv         - base64
 * @param {string} authTag    - base64
 * @returns {string}
 */
function decrypt(ciphertext, iv, authTag) {
  if (!ciphertext || !iv || !authTag) {
    throw new Error('decrypt: ciphertext, iv, and authTag are required');
  }

  const key = getDerivedKey();

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64'),
    { authTagLength: TAG_LENGTH }
  );

  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Generate a cryptographically secure random token.
 * Used for session tokens, room codes, etc.
 *
 * @param {number} bytes - number of random bytes
 * @returns {string} - hex string
 */
function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Generate a short human-readable room code (e.g., "XKCD-9A1B").
 * @returns {string}
 */
function generateRoomCode() {
  const chars  = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No ambiguous chars
  const part1  = Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
  const part2  = Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
  return `${part1}-${part2}`;
}

/**
 * Hash a value with SHA-256 (non-reversible, for fingerprinting).
 * @param {string} value
 * @returns {string} hex digest
 */
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still do comparison to prevent timing leak on length
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
  encrypt,
  decrypt,
  generateToken,
  generateRoomCode,
  sha256,
  safeCompare,
};
