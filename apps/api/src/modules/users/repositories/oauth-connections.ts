import { MCP_READ_SCOPE, MCP_WRITE_SCOPE } from "@openrift/shared/contracts/oauth-connections";
import type { Kysely } from "kysely";
import { sql } from "kysely";

import type { Database } from "../../../db/tables.js";

interface OAuthConnectionRow {
  clientId: string;
  name: string | null;
  scopes: string[];
  updatedAt: Date;
}

export function oauthConnectionsRepo(db: Kysely<Database>) {
  return {
    async listForUser(userId: string): Promise<OAuthConnectionRow[]> {
      const { rows } = await sql<OAuthConnectionRow>`
        SELECT client_id, name, scopes, updated_at
        FROM (
          SELECT DISTINCT ON (c.client_id) c.client_id, app.name, c.scopes, c.updated_at
          FROM oauth_consents c
          JOIN oauth_clients app USING (client_id)
          WHERE c.user_id = ${userId} AND app.disabled IS NOT TRUE
          ORDER BY c.client_id, c.updated_at DESC, c.id DESC
        ) grants
        WHERE scopes ?| ARRAY[${MCP_READ_SCOPE}, ${MCP_WRITE_SCOPE}]
        ORDER BY updated_at DESC, client_id
      `.execute(db);
      return rows;
    },

    async getScopesForUser(userId: string, clientId: string): Promise<string[]> {
      const { rows } = await sql<{ scopes: string[] }>`
        SELECT c.scopes
        FROM oauth_consents c
        JOIN oauth_clients app USING (client_id)
        WHERE c.user_id = ${userId} AND c.client_id = ${clientId} AND app.disabled IS NOT TRUE
        ORDER BY c.updated_at DESC, c.id DESC
        LIMIT 1
      `.execute(db);
      return rows[0]?.scopes ?? [];
    },
  };
}
