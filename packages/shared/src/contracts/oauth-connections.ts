import { z } from "zod";

import { authedRoute } from "./_base.js";

export const MCP_READ_SCOPE = "openrift:read";
export const MCP_WRITE_SCOPE = "openrift:write";
export const OAUTH_OFFLINE_SCOPE = "offline_access";

const oauthConnectionSchema = z.object({
  clientId: z.string(),
  name: z.string().nullable(),
  scopes: z.array(z.string()),
  updatedAt: z.iso.datetime(),
});

export const oauthConnectionsSchema = z.object({ items: z.array(oauthConnectionSchema) });

export const oauthConnectionsContract = {
  listMine: authedRoute
    .route({
      method: "GET",
      path: "/api/v1/me/oauth-connections",
      tags: ["Account"],
      summary: "List connected OAuth clients",
    })
    .meta({ cache: "revalidate" })
    .output(oauthConnectionsSchema),
};
