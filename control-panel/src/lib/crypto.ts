/**
 * AES-256-GCM encrypt/decrypt for the session cookie's contents.
 *
 * The session cookie already carries the properties that matter most
 * (httpOnly, so client JS never reads it; Secure + SameSite=Lax in
 * production) — encrypting the value on top of that is defense in
 * depth: even something that could read cookies off disk/a backup
 * without going through the browser (or a XSS bug that somehow reached
 * `document.cookie` despite httpOnly) gets ciphertext, not a live
 * Keycloak refresh token.
 *
 * Server-only: only ever called from Route Handlers / Server Components
 * (Node.js runtime), never from `proxy.ts` (which runs in a restricted
 * runtime and only ever needs the *presence* of the cookie, never its
 * contents — see `proxy.ts`'s own comment).
 */
import "server-only";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

import { env } from "./env";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // recommended for GCM
const KEY_LENGTH = 32; // AES-256

let cachedKey: Buffer | null = null;

function deriveKey(): Buffer {
  if (cachedKey) return cachedKey;
  // A fixed, non-secret salt is fine here: `SESSION_SECRET` itself is
  // the actual secret material (see .env.local.example), and scrypt is
  // only being used to stretch/normalize it to exactly 32 bytes, not to
  // defend a low-entropy password against offline guessing.
  cachedKey = scryptSync(env.sessionSecret(), "py-authz-control-panel", KEY_LENGTH);
  return cachedKey;
}

/** Encrypt `plaintext`, returning a single base64url string safe to use
 * as a cookie value (`iv:authTag:ciphertext`, all base64url-encoded). */
export function encrypt(plaintext: string): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, deriveKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [iv, authTag, ciphertext].map((buf) => buf.toString("base64url")).join(".");
}

/** Decrypt a value produced by `encrypt()`. Returns `null` (never
 * throws) on any malformed/tampered/wrong-key input — a corrupt or
 * stale-key cookie must be treated as "not logged in," not a crash. */
export function decrypt(value: string): string | null {
  try {
    const [ivB64, authTagB64, ciphertextB64] = value.split(".");
    if (!ivB64 || !authTagB64 || !ciphertextB64) return null;

    const iv = Buffer.from(ivB64, "base64url");
    const authTag = Buffer.from(authTagB64, "base64url");
    const ciphertext = Buffer.from(ciphertextB64, "base64url");

    const decipher = createDecipheriv(ALGORITHM, deriveKey(), iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch {
    return null;
  }
}
