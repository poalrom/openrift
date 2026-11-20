import type { McpServer } from "@modelcontextprotocol/server";
import { createCollectionSchema } from "@openrift/shared/contracts/collections";
import { addCopiesSchema, moveCopiesSchema } from "@openrift/shared/contracts/copies";
import {
  createDeckSchema,
  updateDeckCardsSchema,
  updateDeckSchema,
} from "@openrift/shared/contracts/decks";
import { idParamSchema, withParams } from "@openrift/shared/schemas";
import { call } from "@orpc/server";

import type { ApiContext } from "../../orpc/context.js";
import { collectionsRouter } from "../collections/routes/authenticated-collections.js";
import { copiesRouter } from "../collections/routes/authenticated-copies.js";
import { decksRouter } from "../decks/routes/authenticated-decks.js";
import { toolResult } from "./tools.js";

const write = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };

export function registerMcpWriteTools(server: McpServer, context: ApiContext): void {
  const options = { context };
  server.registerTool(
    "create_collection",
    {
      description: "Create a personal collection. Supply a stable id if you may retry the request.",
      inputSchema: createCollectionSchema.omit({ groupSlug: true, purpose: true }),
      annotations: write,
    },
    (input) => toolResult(context, () => call(collectionsRouter.create, input, options)),
  );
  server.registerTool(
    "add_copies",
    {
      description:
        "Add physical copies by printing ID. Omit collectionId to use the Inbox. Reuse the same batchId for retries.",
      inputSchema: addCopiesSchema,
      annotations: write,
    },
    (input) => toolResult(context, () => call(copiesRouter.add, input, options)),
  );
  server.registerTool(
    "move_copies",
    {
      description: "Move existing physical copies to a collection the signed-in account can edit.",
      inputSchema: moveCopiesSchema.omit({ cancelTradeIds: true }),
      annotations: write,
    },
    (input) => toolResult(context, () => call(copiesRouter.move, input, options)),
  );
  server.registerTool(
    "create_deck",
    {
      description:
        "Create a private, empty deck using an OpenRift format slug such as constructed or freeform. Supply a stable id if you may retry the request.",
      inputSchema: createDeckSchema.omit({ isPublic: true }),
      annotations: write,
    },
    (input) => toolResult(context, () => call(decksRouter.create, input, options)),
  );
  server.registerTool(
    "update_deck",
    {
      description: "Update the supplied settings on a deck owned by the signed-in account.",
      inputSchema: withParams(idParamSchema, updateDeckSchema),
      annotations: write,
    },
    (input) => toolResult(context, () => call(decksRouter.update, input, options)),
  );
  server.registerTool(
    "replace_deck_cards",
    {
      description:
        "Replace the complete card list of one deck. Read get_deck first and pass its version as expectedVersion. Cards omitted here are removed. On a conflict, read the deck again before deciding whether to retry.",
      inputSchema: withParams(
        idParamSchema,
        updateDeckCardsSchema.required({ expectedVersion: true }),
      ),
      annotations: { ...write, destructiveHint: true },
    },
    (input) => toolResult(context, () => call(decksRouter.replaceCards, input, options)),
  );
}
