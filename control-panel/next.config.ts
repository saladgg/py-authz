import type { NextConfig } from "next";

// Security headers are set per request in `src/proxy.ts` (see
// `src/lib/security-headers.ts`), not via `headers()` here: those are
// resolved at build time, but the CSP needs the runtime OIDC issuer.
const nextConfig: NextConfig = {};

export default nextConfig;
