import type { McpServer } from "@modelcontextprotocol/server";
import { searchInputSchema } from "@openrift/shared/contracts/search";
import { idParamSchema } from "@openrift/shared/schemas";
import { call, ORPCError } from "@orpc/server";
import { z } from "zod";

import type { ApiContext } from "../../orpc/context.js";
import { searchRouter } from "../catalog/routes/public-search.js";
import { collectionsRouter } from "../collections/routes/authenticated-collections.js";
import { decksRouter } from "../decks/routes/authenticated-decks.js";

const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

export async function toolResult(context: ApiContext, run: () => Promise<unknown>) {
  try {
    const value = await run();
    return {
      content: [
        { type: "text" as const, text: JSON.stringify(value === undefined ? { ok: true } : value) },
      ],
    };
  } catch (error) {
    if (error instanceof ORPCError && error.status < 500) {
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ code: error.code, message: error.message, data: error.data }),
          },
        ],
      };
    }
    context.log.error({ err: error }, "MCP tool failed");
    return {
      isError: true,
      content: [{ type: "text" as const, text: "OpenRift could not complete this request." }],
    };
  }
}

export function registerMcpReadTools(server: McpServer, context: ApiContext): void {
  const options = { context };
  server.registerTool(
    "search_cards",
    {
      description:
        "Search the Riftbound catalog by name, card number, or OpenRift query syntax. Results include printing IDs and card details. Pass nextCursor to read another page.",
      inputSchema: searchInputSchema.extend({ limit: z.number().int().min(1).max(50).default(20) }),
      annotations: readOnly,
    },
    (input) => toolResult(context, () => call(searchRouter.search, input, options)),
  );
  server.registerTool(
    "list_collections",
    {
      description: "List collections available to the signed-in OpenRift account.",
      annotations: readOnly,
    },
    () => toolResult(context, () => call(collectionsRouter.list, undefined, options)),
  );
  server.registerTool(
    "list_collection_copies",
    {
      description:
        "Read physical copies in one collection. Get the collection ID from list_collections and pass nextCursor to read another page.",
      inputSchema: idParamSchema.extend({
        cursor: z.string().optional(),
        limit: z.number().int().min(1).max(100).default(50),
      }),
      annotations: readOnly,
    },
    (input) => toolResult(context, () => call(collectionsRouter.copies, input, options)),
  );
  server.registerTool(
    "list_decks",
    {
      description: "List the signed-in account's decks, including their missing-card counts.",
      inputSchema: z.object({ includeArchived: z.boolean().optional() }),
      annotations: readOnly,
    },
    ({ includeArchived }) =>
      toolResult(context, () =>
        call(decksRouter.list, { includeArchived: includeArchived ? "true" : undefined }, options),
      ),
  );
  server.registerTool(
    "get_deck",
    {
      description:
        "Read a deck owned by the signed-in account, including its card list and version.",
      inputSchema: idParamSchema,
      annotations: readOnly,
    },
    (input) => toolResult(context, () => call(decksRouter.get, input, options)),
  );
}
