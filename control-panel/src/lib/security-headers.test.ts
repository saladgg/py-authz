import { describe, expect, it } from "vitest";

import { contentSecurityPolicy, securityHeaders } from "./security-headers";

describe("security headers (SEC3-12)", () => {
  const prod = { issuer: "https://idp.example.com/realms/x", isDev: false };

  it("forbids framing (clickjacking of confirm dialogs)", () => {
    const headers = securityHeaders(prod);
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
  });

  it("lets sign-out's form redirect reach the IdP, and nothing else", () => {
    expect(contentSecurityPolicy(prod)).toContain("form-action 'self' https://idp.example.com;");
  });

  it("degrades to 'self' when the issuer is unset or invalid", () => {
    expect(contentSecurityPolicy({ issuer: undefined, isDev: false })).toContain(
      "form-action 'self';",
    );
    expect(contentSecurityPolicy({ issuer: "not a url", isDev: false })).toContain(
      "form-action 'self';",
    );
  });

  it("only allows unsafe-eval in development", () => {
    expect(contentSecurityPolicy(prod)).not.toContain("unsafe-eval");
    expect(contentSecurityPolicy({ ...prod, isDev: true })).toContain("unsafe-eval");
  });

  it("does not force HTTPS upgrades (breaks plain-HTTP deployments)", () => {
    expect(contentSecurityPolicy(prod)).not.toContain("upgrade-insecure-requests");
  });
});
