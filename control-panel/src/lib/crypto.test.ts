import { describe, expect, it } from "vitest";

import { decrypt, encrypt } from "./crypto";

describe("session cookie sealing", () => {
  it("round-trips", () => {
    expect(decrypt(encrypt("hello"))).toBe("hello");
  });

  it("uses a fresh IV every time", () => {
    expect(encrypt("same")).not.toBe(encrypt("same"));
  });

  it("returns null (never throws) for tampered ciphertext", () => {
    const [iv, tag, body] = encrypt("secret").split(".");
    const flipped = body.slice(0, -2) + (body.endsWith("A") ? "BB" : "AA");
    expect(decrypt([iv, tag, flipped].join("."))).toBeNull();
  });

  it("returns null for a truncated auth tag or garbage", () => {
    const [iv, tag, body] = encrypt("secret").split(".");
    expect(decrypt([iv, tag.slice(0, 4), body].join("."))).toBeNull();
    expect(decrypt("not-a-cookie")).toBeNull();
    expect(decrypt("")).toBeNull();
  });
});
