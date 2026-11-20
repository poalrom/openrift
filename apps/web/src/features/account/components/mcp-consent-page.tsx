import {
  MCP_READ_SCOPE,
  MCP_WRITE_SCOPE,
  OAUTH_OFFLINE_SCOPE,
} from "@openrift/shared/contracts/oauth-connections";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "@tanstack/react-router";
import { Clock3Icon, EyeIcon, PencilIcon } from "lucide-react";
import { useId, useState } from "react";
import { z } from "zod";

import { AuthPageLayout } from "@/components/layout/auth-page-layout";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { FieldError } from "@/components/ui/field";
import { Label } from "@/components/ui/label";
import { AuthFormCard } from "@/features/account/components/auth-form-shell";
import { apiFetch } from "@/lib/api-fetch";
import { m } from "@/paraglide/messages.js";

const clientMetadata = z.object({ client_name: z.string().optional() });
const consentResponse = z.object({ url: z.url({ protocol: /^https?$/u }) });

export function McpConsentPage() {
  const search = useLocation({ select: (location) => location.searchStr });
  const params = new URLSearchParams(search);
  const clientId = params.get("client_id");
  const scopes = (params.get("scope") ?? "").split(" ").filter(Boolean);
  const validRequest = clientId !== null && params.has("sig") && scopes.length > 0;
  const wantsRead = scopes.includes(MCP_READ_SCOPE);
  const wantsWrite = scopes.includes(MCP_WRITE_SCOPE);
  const wantsOffline = scopes.includes(OAUTH_OFFLINE_SCOPE);
  const optionalWrite = wantsRead && wantsWrite;
  const [allowWrite, setAllowWrite] = useState(false);
  const writeId = useId();
  const approveLabel = optionalWrite
    ? allowWrite
      ? m.auth_mcp_allow_read_write()
      : m.auth_mcp_allow_read()
    : m.auth_mcp_allow();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const client = useQuery({
    queryKey: ["mcp-client", clientId],
    enabled: validRequest,
    queryFn: async () => {
      const query = new URLSearchParams({ client_id: clientId ?? "" });
      const response = await apiFetch(`/api/auth/oauth2/public-client?${query}`);
      if (!response.ok) {
        return null;
      }
      return clientMetadata.parse(await response.json()).client_name ?? null;
    },
  });

  async function decide(accept: boolean) {
    setPending(true);
    setError(false);
    try {
      // The provider signs repeated parameters that the router may normalize.
      const oauthQuery = globalThis.location.search.slice(1);
      const scope =
        accept && optionalWrite && !allowWrite
          ? scopes.filter((value) => value !== MCP_WRITE_SCOPE).join(" ")
          : undefined;
      const response = await apiFetch("/api/auth/oauth2/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ accept, scope, oauth_query: oauthQuery }),
      });
      if (!response.ok) {
        setError(true);
        setPending(false);
        return;
      }
      const { url } = consentResponse.parse(await response.json());
      globalThis.location.assign(url);
    } catch {
      setError(true);
      setPending(false);
    }
  }

  return (
    <AuthPageLayout size="2xl">
      <AuthFormCard
        layout="single"
        title={m.auth_mcp_title()}
        subtitle={m.auth_mcp_request({
          client: client.data ?? clientId ?? m.auth_mcp_unknown_client(),
        })}
      >
        {validRequest && (
          <>
            <ul className="divide-border divide-y rounded-lg border">
              {wantsRead && (
                <li className="flex items-start gap-3 p-3">
                  <EyeIcon
                    aria-hidden="true"
                    className="text-muted-foreground mt-0.5 size-4 shrink-0"
                  />
                  <div>
                    <p className="text-sm font-medium">{m.auth_mcp_read_label()}</p>
                    <p className="text-muted-foreground text-sm">{m.auth_mcp_read()}</p>
                  </div>
                </li>
              )}
              {wantsWrite && (
                <li className="flex items-start gap-3 p-3">
                  <PencilIcon
                    aria-hidden="true"
                    className="text-muted-foreground mt-0.5 size-4 shrink-0"
                  />
                  <div className="min-w-0 flex-1">
                    {optionalWrite ? (
                      <Label htmlFor={writeId}>{m.auth_mcp_write_label()}</Label>
                    ) : (
                      <p className="text-sm font-medium">{m.auth_mcp_write_label()}</p>
                    )}
                    <p id={`${writeId}-description`} className="text-muted-foreground text-sm">
                      {m.auth_mcp_write()}
                    </p>
                  </div>
                  {optionalWrite && (
                    <Checkbox
                      id={writeId}
                      aria-describedby={`${writeId}-description`}
                      className="mt-0.5"
                      checked={allowWrite}
                      disabled={pending}
                      onCheckedChange={setAllowWrite}
                    />
                  )}
                </li>
              )}
              {wantsOffline && (
                <li className="flex items-start gap-3 p-3">
                  <Clock3Icon
                    aria-hidden="true"
                    className="text-muted-foreground mt-0.5 size-4 shrink-0"
                  />
                  <div>
                    <p className="text-sm font-medium">{m.auth_mcp_offline_label()}</p>
                    <p className="text-muted-foreground text-sm">{m.auth_mcp_offline()}</p>
                  </div>
                </li>
              )}
              {scopes
                .filter(
                  (scope) =>
                    scope !== MCP_READ_SCOPE &&
                    scope !== MCP_WRITE_SCOPE &&
                    scope !== OAUTH_OFFLINE_SCOPE,
                )
                .map((scope) => (
                  <li key={scope} className="p-3 text-sm">
                    {scope}
                  </li>
                ))}
            </ul>
            <div className="flex flex-wrap justify-end gap-2">
              <Button variant="outline" disabled={pending} onClick={() => void decide(false)}>
                {m.auth_mcp_deny()}
              </Button>
              <Button disabled={pending} onClick={() => void decide(true)}>
                {approveLabel}
              </Button>
            </div>
          </>
        )}
        {(error || !validRequest) && <FieldError role="alert">{m.auth_mcp_error()}</FieldError>}
      </AuthFormCard>
    </AuthPageLayout>
  );
}
