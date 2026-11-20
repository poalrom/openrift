import type { BetterAuthPlugin } from "better-auth/types";
import {
  ColumnNode,
  InsertQueryNode,
  PrimitiveValueListNode,
  TableNode,
  UpdateQueryNode,
  ValueListNode,
  ValueNode,
  ValuesNode,
} from "kysely";
import type { KyselyPlugin, OperationNode } from "kysely";

function restoreArray(node: OperationNode): OperationNode {
  if (ValueNode.is(node) && typeof node.value === "string" && node.value.startsWith("[")) {
    const array: unknown = JSON.parse(node.value);
    return ValueNode.create(array);
  }
  return node;
}

/** Undo Better Auth's array serialization before postgres.js encodes the JSONB parameters. */
export function oauthJsonArrays(schema: NonNullable<BetterAuthPlugin["schema"]>): KyselyPlugin {
  const arrayColumns = new Map<string, Set<string>>();
  for (const [model, { modelName, fields }] of Object.entries(schema)) {
    const columns = Object.entries(fields)
      .filter(([, field]) => field.type === "string[]" || field.type === "number[]")
      .map(([name, field]) => field.fieldName ?? name);
    if (columns.length > 0) {
      arrayColumns.set(modelName ?? model, new Set(columns));
    }
  }

  return {
    transformQuery({ node }) {
      if (
        InsertQueryNode.is(node) &&
        node.into &&
        node.columns &&
        node.values &&
        ValuesNode.is(node.values)
      ) {
        const columns = arrayColumns.get(node.into.table.identifier.name);
        if (columns) {
          const isArrayColumn = node.columns.map(({ column }) => columns.has(column.name));
          const rows = node.values.values.map((row) => {
            const values = PrimitiveValueListNode.is(row)
              ? row.values.map((value) => ValueNode.create(value))
              : row.values;
            return ValueListNode.create(
              values.map((value, index) => (isArrayColumn[index] ? restoreArray(value) : value)),
            );
          });
          return { ...node, values: ValuesNode.create(rows) };
        }
      }
      if (UpdateQueryNode.is(node) && node.table && TableNode.is(node.table) && node.updates) {
        const columns = arrayColumns.get(node.table.table.identifier.name);
        if (columns) {
          return {
            ...node,
            updates: node.updates.map((update) =>
              ColumnNode.is(update.column) && columns.has(update.column.column.name)
                ? { ...update, value: restoreArray(update.value) }
                : update,
            ),
          };
        }
      }
      return node;
    },
    transformResult: ({ result }) => Promise.resolve(result),
  };
}
