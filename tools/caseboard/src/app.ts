import express from "express";
import type { ErrorRequestHandler, RequestHandler } from "express";
import { fileURLToPath } from "url";
import path from "path";
import type Database from "better-sqlite3";
import { makeRouter } from "./router.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Headers that stop the UI from loading or running anything it does not ship itself. */
const securityHeaders: RequestHandler = (_req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
};

const jsonErrors: ErrorRequestHandler = (err, _req, res, _next) => {
  const status = typeof err?.status === "number" && err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? "internal error" : "invalid request body" });
};

export function createApp(db: Database.Database) {
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders);
  app.use(express.json({ limit: "256kb" }));
  app.use(express.static(path.join(__dirname, "public")));
  app.use("/api", makeRouter(db));
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "not found" });
  });
  app.use(jsonErrors);
  return app;
}
