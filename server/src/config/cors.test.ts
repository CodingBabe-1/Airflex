import express from "express";
import cors from "cors";
import request from "supertest";
import {
  buildCorsOptions,
  isOriginAllowed,
  parseAllowedOrigins,
  validateCorsEnv,
} from "./cors";
import { validateEnv } from "./validateEnv";

describe("CORS allowlist (issue #539)", () => {
  describe("parseAllowedOrigins", () => {
    it("parses and normalises a comma-separated allowlist", () => {
      const allowed = parseAllowedOrigins({
        NODE_ENV: "production",
        CORS_ALLOWED_ORIGINS: " https://airflex.app/ , https://www.airflex.app,https://airflex.app",
      });
      expect(allowed).toEqual({
        allowAll: false,
        origins: ["https://airflex.app", "https://www.airflex.app"],
      });
    });

    it("falls back to the legacy CORS_ORIGIN variable", () => {
      expect(parseAllowedOrigins({ CORS_ORIGIN: "https://airflex.app" }).origins).toEqual([
        "https://airflex.app",
      ]);
    });

    it("throws on a wildcard in production", () => {
      expect(() =>
        parseAllowedOrigins({ NODE_ENV: "production", CORS_ALLOWED_ORIGINS: "*" })
      ).toThrow(/not allowed in production/);
    });

    it("honours a wildcard outside production", () => {
      expect(parseAllowedOrigins({ NODE_ENV: "development", CORS_ALLOWED_ORIGINS: "*" }).allowAll).toBe(true);
    });

    it("fails closed in production when unset, defaults to localhost in development", () => {
      expect(parseAllowedOrigins({ NODE_ENV: "production" }).origins).toEqual([]);
      expect(parseAllowedOrigins({ NODE_ENV: "development" }).origins).toEqual(["http://localhost:3000"]);
    });
  });

  describe("isOriginAllowed", () => {
    const allowed = { allowAll: false, origins: ["https://airflex.app"] };

    it("matches exact origins only", () => {
      expect(isOriginAllowed("https://airflex.app", allowed)).toBe(true);
      expect(isOriginAllowed("https://evil.airflex.app", allowed)).toBe(false);
      expect(isOriginAllowed("http://airflex.app", allowed)).toBe(false);
      expect(isOriginAllowed("https://airflex.app.evil.com", allowed)).toBe(false);
      expect(isOriginAllowed("null", allowed)).toBe(false);
    });
  });

  describe("validateEnv integration", () => {
    const base = {
      JWT_SECRET: "a_long_random_string_at_least_32_chars",
      DATABASE_URL: "postgresql://postgres:password@localhost:5432/airflex",
      ENCRYPTION_KEY: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      STELLAR_SERVER_SECRET: "S000000000000000000000000000000000000000000000000000000",
      PLATFORM_TREASURY_USER_ID: "00000000-0000-0000-0000-000000000000",
      PAYSTACK_SECRET_KEY: "sk_test_1234567890",
      TERMII_API_KEY: "TL12345678901234567890",
      REDIS_URL: "redis://localhost:6379",
      NODE_ENV: "production",
    };

    it("refuses to boot with a wildcard origin in production", () => {
      const result = validateEnv({ ...base, CORS_ALLOWED_ORIGINS: "https://airflex.app,*" });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes("Wildcard CORS origin"))).toBe(true);
    });

    it("rejects malformed origins", () => {
      expect(validateCorsEnv({ CORS_ALLOWED_ORIGINS: "airflex.app" })[0]).toMatch(/Invalid CORS origin/);
    });

    it("accepts an explicit allowlist in production", () => {
      expect(validateEnv({ ...base, CORS_ALLOWED_ORIGINS: "https://airflex.app" }).valid).toBe(true);
    });
  });

  describe("middleware behaviour", () => {
    function buildApp() {
      const app = express();
      app.use(cors(buildCorsOptions({ NODE_ENV: "production", CORS_ALLOWED_ORIGINS: "https://airflex.app" })));
      app.options("*", (_req, res) => {
        res.status(204).end();
      });
      // Stand-in for an authenticated route: rejects anything without a token.
      app.get("/api/v1/profile", (req, res) => {
        if (!req.headers.authorization) {
          res.status(401).json({ error: "Missing or invalid Authorization header" });
          return;
        }
        res.json({ ok: true });
      });
      return app;
    }

    it("answers a preflight from an allowlisted origin with 204 and CORS headers", async () => {
      const res = await request(buildApp())
        .options("/api/v1/profile")
        .set("Origin", "https://airflex.app")
        .set("Access-Control-Request-Method", "GET")
        .set("Access-Control-Request-Headers", "authorization,idempotency-key");

      expect(res.status).toBe(204);
      expect(res.headers["access-control-allow-origin"]).toBe("https://airflex.app");
      expect(res.headers["access-control-allow-headers"]).toMatch(/Authorization/);
      expect(res.headers["access-control-allow-headers"]).toMatch(/Idempotency-Key/);
      expect(res.headers["vary"]).toMatch(/Origin/);
    });

    it("omits CORS headers for an unlisted origin", async () => {
      const res = await request(buildApp())
        .options("/api/v1/profile")
        .set("Origin", "https://evil.example")
        .set("Access-Control-Request-Method", "GET");

      expect(res.status).toBe(204);
      expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    });

    it("reflects the exact allowlisted origin, never a wildcard", async () => {
      const res = await request(buildApp())
        .get("/api/v1/profile")
        .set("Origin", "https://airflex.app")
        .set("Authorization", "Bearer x");

      expect(res.headers["access-control-allow-origin"]).toBe("https://airflex.app");
    });
  });
});
