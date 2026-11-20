import { createHash, randomBytes, randomUUID } from "node:crypto";

import { createLogger } from "@openrift/shared/logger";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";

import { createApp } from "../../app.js";
import { createAuth } from "../../auth.js";
import { createConfig } from "../../config.js";
import { createDb } from "../../db/connect.js";
import { MCP_PATH, MCP_SCOPE } from "./config.js";

const databaseUrl = process.env.INTEGRATION_DB_URL;
const origin = "http://localhost:5173";
const resource = `${origin}${MCP_PATH}`;
const redirectUri = "http://127.0.0.1:44771/callback";
const redirectReply = z.object({ url: z.string() });
const tokenReply = z.object({ access_token: z.string(), refresh_token: z.string() });
const toolReply = z.object({
  result: z.object({
    isError: z.boolean().optional(),
    content: z.array(z.object({ text: z.string() })),
  }),
});

describe.skipIf(!databaseUrl)("OpenRift MCP OAuth", () => {
  const { db, dialect } = createDb(databaseUrl ?? "");
  const config = createConfig({
    BETTER_AUTH_URL: origin,
    BETTER_AUTH_SECRET: "openrift-mcp-integration-secret-32-chars",
    CORS_ORIGIN: origin,
    DISABLE_AUTH_RATE_LIMIT: "1",
  });
  const auth = createAuth({ db, dialect, config, sendEmail: () => Promise.resolve(undefined) });
  const app = createApp({ db, auth, config, log: createLogger("test", "silent") });
  const password = randomUUID();
  const readerEmail = `mcp-reader-${randomUUID()}@test.example`;
  let otherCollectionId: string;
  let readerId: string;
  let otherId: string;

  beforeAll(async () => {
    const [reader, other] = await Promise.all([
      auth.api.signUpEmail({ body: { name: "Reader", email: readerEmail, password } }),
      auth.api.signUpEmail({
        body: { name: "Other", email: `mcp-other-${randomUUID()}@test.example`, password },
      }),
    ]);
    readerId = reader.user.id;
    otherId = other.user.id;
    await db.updateTable("users").set({ emailVerified: true }).where("id", "=", readerId).execute();
    const collection = await db
      .selectFrom("collections")
      .select("id")
      .where("userId", "=", otherId)
      .executeTakeFirstOrThrow();
    otherCollectionId = collection.id;
  });

  afterAll(async () => {
    await db.deleteFrom("users").where("id", "in", [readerId, otherId].filter(Boolean)).execute();
    await db.destroy();
  });

  function post(path: string, body: unknown, headers?: Record<string, string>) {
    const requestHeaders = new Headers(headers);
    requestHeaders.set("Content-Type", "application/json");
    requestHeaders.set("Accept", "application/json");
    requestHeaders.set("Origin", origin);
    return app.request(`${origin}${path}`, {
      method: "POST",
      headers: requestHeaders,
      body: JSON.stringify(body),
    });
  }

  async function mcpRequest(method: string, params: unknown, token?: string) {
    const headers = new Headers({
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    });
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    return app.request(resource, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
  }

  async function mcpResult(response: Response): Promise<unknown> {
    expect(response.status).toBe(200);
    if (response.headers.get("content-type")?.startsWith("text/event-stream")) {
      const stream = await response.text();
      const message = stream.split("\n").find((line) => line.startsWith("data: "));
      return JSON.parse(message?.slice(6) ?? "null");
    }
    return response.json();
  }

  it("challenges unauthenticated clients and discovers the OpenRift authorization server", async () => {
    const challenge = await mcpRequest("tools/list", {});
    expect(challenge.status).toBe(401);
    expect(challenge.headers.get("www-authenticate")).toContain(
      `${origin}/.well-known/oauth-protected-resource/api/mcp`,
    );
    expect(challenge.headers.get("cache-control")).toBe("no-store");
    const metadata = await app.request(`${origin}/.well-known/oauth-protected-resource/api/mcp`);
    expect(await metadata.json()).toMatchObject({
      resource,
      scopes_supported: [MCP_SCOPE],
      authorization_servers: [`${origin}/api/auth`],
    });
    const authorization = await app.request(
      `${origin}/.well-known/oauth-authorization-server/api/auth`,
    );
    expect(await authorization.json()).toMatchObject({
      registration_endpoint: `${origin}/api/auth/oauth2/register`,
      code_challenge_methods_supported: ["S256"],
    });
  });

  it("continues from password sign-in through consent and reads only authorized collections", async () => {
    const scope = `${MCP_SCOPE} offline_access`;
    const registration = await post("/api/auth/oauth2/register", {
      client_name: "Integration test",
      application_type: "native",
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      scope,
    });
    expect(registration.status).toBe(201);
    const { client_id: clientId } = z
      .object({ client_id: z.string() })
      .parse(await registration.json());
    const verifier = randomBytes(32).toString("base64url");
    const authorizeQuery = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope,
      resource,
      state: randomUUID(),
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
    });
    const authorize = await app.request(`${origin}/api/auth/oauth2/authorize?${authorizeQuery}`, {
      headers: { Accept: "text/html" },
    });
    expect(authorize.status).toBe(302);
    const login = new URL(authorize.headers.get("Location") ?? "", origin);
    expect(login.pathname).toBe("/login");

    const signedIn = await post("/api/auth/sign-in/email", {
      email: readerEmail,
      password,
      oauth_query: login.search.slice(1),
    });
    expect(signedIn.status).toBe(200);
    const consent = new URL(redirectReply.parse(await signedIn.json()).url, origin);
    expect(consent.pathname).toBe("/mcp/consent");
    const cookie = signedIn.headers
      .getSetCookie()
      .map((value) => value.split(";")[0])
      .join("; ");
    const clientMetadata = await app.request(
      `${origin}/api/auth/oauth2/public-client?client_id=${clientId}`,
      { headers: { Cookie: cookie } },
    );
    expect(await clientMetadata.json()).toMatchObject({ client_name: "Integration test" });
    const decision = await post(
      "/api/auth/oauth2/consent",
      { accept: true, oauth_query: consent.search.slice(1) },
      { Cookie: cookie },
    );
    expect(decision.status).toBe(200);
    const callback = new URL(redirectReply.parse(await decision.json()).url);
    expect(callback.searchParams.get("state")).toBe(authorizeQuery.get("state"));
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();

    const token = await app.request(`${origin}/api/auth/oauth2/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        code: code ?? "",
        code_verifier: verifier,
        redirect_uri: redirectUri,
        resource,
      }),
    });
    expect(token.status).toBe(200);
    const { access_token: accessToken, refresh_token: refreshToken } = tokenReply.parse(
      await token.json(),
    );
    const initialized = await mcpResult(
      await mcpRequest(
        "initialize",
        {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "integration", version: "1.0.0" },
        },
        accessToken,
      ),
    );
    expect(initialized).toMatchObject({
      result: { protocolVersion: "2025-11-25", serverInfo: { name: "openrift" } },
    });
    const tools = await mcpResult(await mcpRequest("tools/list", {}, accessToken));
    expect(tools).toMatchObject({
      result: {
        tools: [
          { name: "search_cards" },
          { name: "list_collections" },
          { name: "list_collection_copies" },
          { name: "list_decks" },
          { name: "get_deck" },
        ],
      },
    });
    const result = toolReply.parse(
      await mcpResult(await mcpRequest("tools/call", { name: "list_collections" }, accessToken)),
    ).result;
    expect(result.isError).toBeUndefined();
    expect(result.content[0]?.text).toContain("Inbox");
    expect(result.content[0]?.text).not.toContain(otherCollectionId);

    const denied = toolReply.parse(
      await mcpResult(
        await mcpRequest(
          "tools/call",
          { name: "list_collection_copies", arguments: { id: otherCollectionId } },
          accessToken,
        ),
      ),
    ).result;
    expect(denied.isError).toBe(true);

    const refresh = await app.request(`${origin}/api/auth/oauth2/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: refreshToken,
        resource,
      }),
    });
    expect(refresh.status).toBe(200);
    const nextToken = tokenReply.parse(await refresh.json()).access_token;
    const nextTools = await mcpRequest("tools/list", {}, nextToken);
    expect(nextTools.status).toBe(200);
  });
});
