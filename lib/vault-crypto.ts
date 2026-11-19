// Server-only vault crypto: AES-256-GCM via node:crypto.
//
// The vault encryption key comes from the VAULT_ENCRYPTION_KEY env var
// (base64 of 32 random bytes — generate with `openssl rand -base64 32`)
// and is never stored in the repo. The admin passphrase comes from
// VAULT_ADMIN_PASS. Both must be set in Vercel for the vault to work;
// without them every vault route answers 503 "not configured" instead of
// failing open.
//
// This file imports only node:crypto, so it can be unit-tested without a
// database. It must never be imported by client components.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export class VaultNotConfigured extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "VaultNotConfigured";
  }
}

/** Base64-encoded 32-byte key from VAULT_ENCRYPTION_KEY. */
export function getEncryptionKey(): Buffer {
  const raw = process.env.VAULT_ENCRYPTION_KEY;
  if (!raw) {
    throw new VaultNotConfigured(
      "VAULT_ENCRYPTION_KEY is not set. Generate one with " +
        "`openssl rand -base64 32` and set it in Vercel (Project → " +
        "Settings → Environment Variables).",
    );
  }
  let key: Buffer;
  try {
    key = Buffer.from(raw.trim(), "base64");
  } catch {
    throw new VaultNotConfigured(
      "VAULT_ENCRYPTION_KEY is not valid base64. It must be base64 of " +
        "32 random bytes (`openssl rand -base64 32`).",
    );
  }
  if (key.length !== 32) {
    throw new VaultNotConfigured(
      `VAULT_ENCRYPTION_KEY must decode to 32 bytes, got ${key.length}. ` +
        "Generate it with `openssl rand -base64 32`.",
    );
  }
  return key;
}

export interface SealedSecret {
  /** base64, 12 random bytes, fresh per entry */
  iv: string;
  /** base64, ciphertext with the 16-byte GCM auth tag appended */
  data: string;
}

/** AES-256-GCM seal. Returns only base64 strings — safe to store. */
export function encryptSecret(plaintext: string): SealedSecret {
  const key = getEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    data: Buffer.concat([ciphertext, tag]).toString("base64"),
  };
}

/** AES-256-GCM open. Throws on a wrong key, tampered data, or bad input. */
export function decryptSecret(sealed: SealedSecret): string {
  const key = getEncryptionKey();
  const iv = Buffer.from(sealed.iv, "base64");
  const raw = Buffer.from(sealed.data, "base64");
  if (iv.length !== 12 || raw.length < 17) {
    throw new Error("Malformed sealed secret.");
  }
  const ciphertext = raw.subarray(0, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}

/** SHA-256 hex of a string (used for fingerprints and admin-pass checks). */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Admin gate: constant-time comparison of the supplied passphrase against
 * VAULT_ADMIN_PASS (compared as SHA-256 digests so the raw value is never
 * held in a comparable string). Returns false when the env var is unset —
 * the vault then refuses every reveal/rotate with "not configured".
 */
export function verifyAdminPass(candidate: string): boolean {
  const expected = process.env.VAULT_ADMIN_PASS;
  if (!expected || !candidate) return false;
  const a = Buffer.from(sha256Hex(candidate), "utf8");
  const b = Buffer.from(sha256Hex(expected), "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Human-readable setup state for the UI when the vault cannot run. */
export function vaultSetupStatus(): {
  configured: boolean;
  db: boolean;
  encryptionKey: boolean;
  adminPass: boolean;
  reason: string | null;
} {
  const db = Boolean(
    process.env.POSTGRES_URL || process.env.DATABASE_URL,
  );
  let encryptionKey = false;
  try {
    getEncryptionKey();
    encryptionKey = true;
  } catch {
    encryptionKey = false;
  }
  const adminPass = Boolean(process.env.VAULT_ADMIN_PASS);
  const missing: string[] = [];
  if (!db) missing.push("a Vercel Postgres database (Storage → Create → Postgres)");
  if (!encryptionKey) missing.push("VAULT_ENCRYPTION_KEY (`openssl rand -base64 32`)");
  if (!adminPass) missing.push("VAULT_ADMIN_PASS");
  return {
    configured: missing.length === 0,
    db,
    encryptionKey,
    adminPass,
    reason:
      missing.length === 0
        ? null
        : `Vault is not configured yet. Still needed: ${missing.join("; ")}. ` +
          "Set them in Vercel (Project → Settings → Environment Variables, " +
          "or Storage for Postgres) and redeploy.",
  };
}
