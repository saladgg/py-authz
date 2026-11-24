import { beforeEach, describe, expect, it, vi } from "vitest";

const jar = new Map<string, string>();

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) => (jar.has(name) ? { value: jar.get(name) } : undefined),
    set: (name: string, value: string) => void jar.set(name, value),
    delete: (name: string) => void jar.delete(name),
  }),
}));

const { encrypt } = await import("./crypto");
const { readSession, SESSION_COOKIE_NAME, SESSION_MAX_AGE_SECONDS } = await import("./session");

function seal(session: Record<string, unknown>) {
  jar.set(SESSION_COOKIE_NAME, encrypt(JSON.stringify(session)));
}

describe("session absolute lifetime (SEC3-12)", () => {
  beforeEach(() => jar.clear());

  const base = { accessToken: "at", refreshToken: "rt", expiresAt: Date.now() + 60_000 };

  it("accepts a session within its lifetime", async () => {
    seal({ ...base, issuedAt: Date.now() - 60_000 });
    expect(await readSession()).not.toBeNull();
  });

  it("rejects a session past its absolute lifetime, even if the cookie survived", async () => {
    seal({ ...base, issuedAt: Date.now() - (SESSION_MAX_AGE_SECONDS + 60) * 1000 });
    expect(await readSession()).toBeNull();
  });

  it("treats a pre-issuedAt session as expired rather than unlimited", async () => {
    seal(base);
    expect(await readSession()).toBeNull();
  });
});
