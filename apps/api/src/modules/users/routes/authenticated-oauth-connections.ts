import { oauthConnectionsContract } from "@openrift/shared/contracts/oauth-connections";
import { implement } from "@orpc/server";

import { requireAuthedUser } from "../../../orpc/base.js";
import type { ApiContext } from "../../../orpc/context.js";

const os = implement(oauthConnectionsContract).$context<ApiContext>().use(requireAuthedUser);

export const oauthConnectionsRouter = {
  listMine: os.listMine.handler(async ({ context }) => {
    const rows = await context.repos.oauthConnections.listForUser(context.userId);
    return { items: rows.map((row) => ({ ...row, updatedAt: row.updatedAt.toISOString() })) };
  }),
};
