import { beforeEach, describe, expect, it, vi } from "vitest";

const revoked: string[] = [];
let cleared = 0;

vi.mock("@/lib/session", () => ({
  readSession: async () => ({ refreshToken: "rt-123" }),
  clearSessionCookie: async () => {
    cleared += 1;
  },
}));
vi.mock("@/lib/oidc", () => ({
  revokeRefreshToken: async ({ refreshToken }: { refreshToken: string }) => {
    revoked.push(refreshToken);
  },
  buildEndSessionUrl: async () => "https://idp.example.com/logout?client_id=control-panel",
}));

const { POST } = await import("./route");

function request(headers: Record<string, string>) {
  return new Request("https://panel.example.com/api/auth/logout", { method: "POST", headers });
}

describe("POST /api/auth/logout (SEC3-12)", () => {
  beforeEach(() => {
    revoked.length = 0;
    cleared = 0;
  });

  it("revokes the refresh token, clears the cookie and ends the IdP session", async () => {
    const res = await POST(request({ origin: "https://panel.example.com" }));

    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toContain("https://idp.example.com/logout");
    expect(revoked).toEqual(["rt-123"]);
    expect(cleared).toBe(1);
  });

  it("refuses a cross-site request", async () => {
    const res = await POST(request({ origin: "https://evil.example.com" }));

    expect(res.status).toBe(403);
    expect(cleared).toBe(0);
  });

  it("refuses when the browser reports a cross-site fetch without an Origin", async () => {
    const res = await POST(request({ "sec-fetch-site": "cross-site" }));

    expect(res.status).toBe(403);
  });
});
