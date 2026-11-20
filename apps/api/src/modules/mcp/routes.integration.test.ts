import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  MCP_READ_SCOPE,
  MCP_WRITE_SCOPE,
  OAUTH_OFFLINE_SCOPE,
} from "@openrift/shared/contracts/oauth-connections";
import { createLogger } from "@openrift/shared/logger";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";

import { createApp } from "../../app.js";
import { createAuth } from "../../auth.js";
import { createConfig } from "../../config.js";
import { createDb } from "../../db/connect.js";
import { MCP_PATH } from "./config.js";

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
  const otherEmail = `mcp-other-${randomUUID()}@test.example`;
  const readerEmail = `mcp-reader-${randomUUID()}@test.example`;
  let otherCollectionId: string;
  let readerId: string;
  let otherId: string;

  beforeAll(async () => {
    const [reader, other] = await Promise.all([
      auth.api.signUpEmail({ body: { name: "Reader", email: readerEmail, password } }),
      auth.api.signUpEmail({
        body: { name: "Other", email: otherEmail, password },
      }),
    ]);
    readerId = reader.user.id;
    otherId = other.user.id;
    await db
      .updateTable("users")
      .set({ emailVerified: true })
      .where("id", "in", [readerId, otherId])
      .execute();
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
      scopes_supported: [MCP_READ_SCOPE, MCP_WRITE_SCOPE],
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

  async function grant(clientName: string, approvedScope?: string) {
    const scope = [MCP_READ_SCOPE, MCP_WRITE_SCOPE, OAUTH_OFFLINE_SCOPE].join(" ");
    const registration = await post("/api/auth/oauth2/register", {
      client_name: clientName,
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
    expect(await clientMetadata.json()).toMatchObject({ client_name: clientName });
    const decision = await post(
      "/api/auth/oauth2/consent",
      { accept: true, scope: approvedScope, oauth_query: consent.search.slice(1) },
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
    return { ...tokenReply.parse(await token.json()), clientId, cookie };
  }

  it("narrows a write request to read access and refuses a direct write", async () => {
    const {
      access_token: accessToken,
      refresh_token: refreshToken,
      clientId,
      cookie,
    } = await grant("Read-only client", `${MCP_READ_SCOPE} ${OAUTH_OFFLINE_SCOPE}`);
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

    const forbiddenCollectionId = randomUUID();
    const attempt = await mcpResult(
      await mcpRequest(
        "tools/call",
        { name: "create_collection", arguments: { id: forbiddenCollectionId, name: "Forbidden" } },
        accessToken,
      ),
    );
    expect(attempt).toMatchObject({ error: { code: -32_602 } });
    const forbiddenCollection = await db
      .selectFrom("collections")
      .select("id")
      .where("id", "=", forbiddenCollectionId)
      .executeTakeFirst();
    expect(forbiddenCollection).toBeUndefined();

    const connections = await app.request(`${origin}/api/v1/me/oauth-connections`, {
      headers: { Cookie: cookie },
    });
    expect(await connections.json()).toMatchObject({
      items: [
        { clientId, name: "Read-only client", scopes: [MCP_READ_SCOPE, OAUTH_OFFLINE_SCOPE] },
      ],
    });

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

  it("writes only after approval and lists each account's own OAuth clients", async () => {
    const { access_token: accessToken, clientId, cookie } = await grant("Read and write client");
    const response = await mcpResult(await mcpRequest("tools/list", {}, accessToken));
    const {
      result: { tools },
    } = z
      .object({
        result: z.object({
          tools: z.array(
            z.object({
              name: z.string(),
              annotations: z.object({ readOnlyHint: z.boolean() }),
            }),
          ),
        }),
      })
      .parse(response);
    expect(tools).toEqual(
      expect.arrayContaining([
        { name: "create_collection", annotations: { readOnlyHint: false } },
        { name: "add_copies", annotations: { readOnlyHint: false } },
        { name: "replace_deck_cards", annotations: { readOnlyHint: false } },
      ]),
    );

    const collectionId = randomUUID();
    const created = toolReply.parse(
      await mcpResult(
        await mcpRequest(
          "tools/call",
          {
            name: "create_collection",
            arguments: { id: collectionId, name: "From MCP" },
          },
          accessToken,
        ),
      ),
    ).result;
    expect(created.isError).toBeUndefined();
    const stored = await db
      .selectFrom("collections")
      .select(["userId", "name"])
      .where("id", "=", collectionId)
      .executeTakeFirstOrThrow();
    expect(stored).toEqual({ userId: readerId, name: "From MCP" });

    const deckId = randomUUID();
    const deck = toolReply.parse(
      await mcpResult(
        await mcpRequest(
          "tools/call",
          {
            name: "create_deck",
            arguments: { id: deckId, name: "Deck from MCP", format: "freeform" },
          },
          accessToken,
        ),
      ),
    ).result;
    expect(deck.isError).toBeUndefined();
    const deckDetail = toolReply.parse(
      await mcpResult(
        await mcpRequest(
          "tools/call",
          {
            name: "get_deck",
            arguments: { id: deckId },
          },
          accessToken,
        ),
      ),
    ).result;
    const { version } = z
      .object({ version: z.string() })
      .parse(JSON.parse(deckDetail.content[0]?.text ?? "null"));
    const replaced = toolReply.parse(
      await mcpResult(
        await mcpRequest(
          "tools/call",
          {
            name: "replace_deck_cards",
            arguments: { id: deckId, cards: [], expectedVersion: version },
          },
          accessToken,
        ),
      ),
    ).result;
    expect(replaced.isError).toBeUndefined();
    const stale = toolReply.parse(
      await mcpResult(
        await mcpRequest(
          "tools/call",
          {
            name: "replace_deck_cards",
            arguments: { id: deckId, cards: [], expectedVersion: version },
          },
          accessToken,
        ),
      ),
    ).result;
    expect(stale.isError).toBe(true);

    const profile = await app.request(`${origin}/api/v1/me/oauth-connections`, {
      headers: { Cookie: cookie },
    });
    expect(await profile.json()).toMatchObject({
      items: expect.arrayContaining([
        expect.objectContaining({
          clientId,
          name: "Read and write client",
          scopes: [MCP_READ_SCOPE, MCP_WRITE_SCOPE, OAUTH_OFFLINE_SCOPE],
        }),
      ]),
    });

    const other = await post("/api/auth/sign-in/email", { email: otherEmail, password });
    const otherCookie = other.headers
      .getSetCookie()
      .map((value) => value.split(";")[0])
      .join("; ");
    const otherProfile = await app.request(`${origin}/api/v1/me/oauth-connections`, {
      headers: { Cookie: otherCookie },
    });
    expect(await otherProfile.json()).toEqual({ items: [] });

    const consents = await app.request(`${origin}/api/auth/oauth2/get-consents`, {
      headers: { Cookie: cookie },
    });
    const granted = z
      .array(z.object({ id: z.string(), clientId: z.string() }))
      .parse(await consents.json())
      .find((consent) => consent.clientId === clientId);
    const reduced = await post(
      "/api/auth/oauth2/update-consent",
      {
        id: granted?.id,
        update: { scopes: [MCP_READ_SCOPE] },
      },
      { Cookie: cookie },
    );
    expect(reduced.status).toBe(200);
    expect(await reduced.json()).toMatchObject({ scopes: [MCP_READ_SCOPE] });
    const narrowedTools = await mcpResult(await mcpRequest("tools/list", {}, accessToken));
    expect(narrowedTools).not.toMatchObject({
      result: {
        tools: expect.arrayContaining([expect.objectContaining({ name: "create_collection" })]),
      },
    });
  });
});
