export const MCP_PATH = "/api/mcp";
export const MCP_DISCOVERY_PATHS = [
  "/.well-known/oauth-protected-resource",
  `/.well-known/oauth-protected-resource${MCP_PATH}`,
  "/.well-known/oauth-authorization-server/api/auth",
];

export function mcpResourceUrl(origin: string | undefined): string | undefined {
  if (!origin) {
    return undefined;
  }
  const url = new URL(origin);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  return url.protocol === "https:" || (url.protocol === "http:" && loopback)
    ? new URL(MCP_PATH, origin).href
    : undefined;
}
