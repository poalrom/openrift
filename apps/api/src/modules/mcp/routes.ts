import { requireMcpAuth } from "@better-auth/mcp";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import type { Hono } from "hono";
import { rateLimiter } from "hono-rate-limiter";

import { buildApiContext } from "../../orpc/context.js";
import type { Auth, Config, Variables } from "../../types.js";
import { MCP_DISCOVERY_PATHS, MCP_PATH, MCP_SCOPE, mcpResourceUrl } from "./config.js";
import { registerMcpTools } from "./tools.js";

export function mountMcp(app: Hono<{ Variables: Variables }>, auth: Auth, config: Config): void {
  const resource = mcpResourceUrl(config.siteOrigin);
  if (!resource) {
    return;
  }
  for (const path of MCP_DISCOVERY_PATHS) {
    app.get(path, (c) => auth.handler(c.req.raw));
    app.on("HEAD", path, (c) => auth.handler(c.req.raw));
  }

  app.use(MCP_PATH, async (c, next) => {
    c.header("Cache-Control", "no-store");
    const origin = c.req.header("origin");
    if (origin && origin !== config.siteOrigin) {
      return c.json({ error: "Origin not allowed" }, 403);
    }
    await next();
  });
  app.use(
    MCP_PATH,
    rateLimiter({
      windowMs: 60_000,
      limit: 120,
      standardHeaders: "draft-6",
      keyGenerator: (c) => c.req.header("x-real-ip") ?? "unknown",
    }),
  );
  // Each tool closes over this request's OAuth subject. Better Auth caches JWKS by auth context.
  app.post(MCP_PATH, (c) =>
    requireMcpAuth(
      auth,
      async (request, claims) => {
        if (!claims.sub) {
          return c.json({ error: "A user access token is required" }, 403);
        }
        const { internalAdapter } = await auth.$context;
        const user = await internalAdapter.findUserById(claims.sub);
        if (!user) {
          return c.json({ error: "Account no longer exists" }, 403);
        }
        const context = buildApiContext(c);
        context.user = user;
        context.loadUser = () => Promise.resolve(user);
        const handler = createMcpHandler(
          () => {
            const server = new McpServer({ name: "openrift", version: "1.0.0" });
            registerMcpTools(server, context);
            return server;
          },
          { maxRequestBodySize: 64 * 1024 },
        );
        try {
          return await handler.fetch(request);
        } finally {
          await handler.close();
        }
      },
      { resource, requiredScopes: [MCP_SCOPE] },
    )(c.req.raw),
  );
  app.all(MCP_PATH, (c) => c.body(null, 405, { Allow: "POST" }));
}
