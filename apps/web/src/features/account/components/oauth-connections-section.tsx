import {
  MCP_READ_SCOPE,
  MCP_WRITE_SCOPE,
  OAUTH_OFFLINE_SCOPE,
  oauthConnectionsSchema,
} from "@openrift/shared/contracts/oauth-connections";
import { formatDay } from "@openrift/shared/format-date";
import { useQuery } from "@tanstack/react-query";

import { SettingsSection } from "@/components/layout/settings-section";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { RowList, RowListItem } from "@/components/ui/row-list";
import { useRequiredUserId } from "@/hooks/use-session";
import { apiFetch } from "@/lib/api-fetch";
import { m } from "@/paraglide/messages.js";

export function OAuthConnectionsSection() {
  const userId = useRequiredUserId();
  const { data, isPending, isError } = useQuery({
    queryKey: ["oauth-connections", userId],
    queryFn: async ({ signal }) => {
      const response = await apiFetch("/api/v1/me/oauth-connections", {
        signal,
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`OAuth connections: ${response.status}`);
      }
      return oauthConnectionsSchema.parse(await response.json()).items;
    },
  });

  return (
    <SettingsSection title={m.profile_oauth_title()} description={m.profile_oauth_description()}>
      {isPending && <p className="text-muted-foreground text-sm">{m.common_loading()}</p>}
      {isError && (
        <Alert variant="destructive">
          <AlertDescription>{m.profile_oauth_load_failed()}</AlertDescription>
        </Alert>
      )}
      {data?.length === 0 && (
        <p className="text-muted-foreground text-sm">{m.profile_oauth_empty()}</p>
      )}
      {data && data.length > 0 && (
        <RowList variant="divided">
          {data.map((client) => (
            <RowListItem key={client.clientId} className="flex-wrap justify-between">
              <div className="min-w-0">
                <p className="font-medium wrap-break-word">{client.name || client.clientId}</p>
                <p className="text-muted-foreground text-sm">
                  {m.profile_oauth_updated({ date: formatDay(client.updatedAt) })}
                </p>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {client.scopes.includes(MCP_READ_SCOPE) && (
                  <Badge variant="neutral">{m.auth_mcp_read_label()}</Badge>
                )}
                {client.scopes.includes(MCP_WRITE_SCOPE) && (
                  <Badge variant="warning">{m.auth_mcp_write_label()}</Badge>
                )}
                {client.scopes.includes(OAUTH_OFFLINE_SCOPE) && (
                  <Badge variant="neutral">{m.auth_mcp_offline_label()}</Badge>
                )}
              </div>
            </RowListItem>
          ))}
        </RowList>
      )}
    </SettingsSection>
  );
}
