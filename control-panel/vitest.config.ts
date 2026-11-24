import path from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
      // `server-only` throws when imported outside Next's react-server
      // environment; in unit tests the modules run in plain Node.
      "server-only": path.resolve(__dirname, "src/test/server-only-stub.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    env: {
      SESSION_SECRET: "test-session-secret-at-least-32-characters-long",
      OIDC_ISSUER: "https://idp.example.com/realms/test",
      OIDC_CLIENT_ID: "control-panel",
      OIDC_REDIRECT_URI: "https://panel.example.com/api/auth/callback",
      CONTROL_PLANE_API_URL: "https://api.example.com",
    },
  },
});
