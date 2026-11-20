import { useQuery } from "@tanstack/react-query";
import { useLocation } from "@tanstack/react-router";
import { useState } from "react";
import { z } from "zod";

import { AuthPageLayout } from "@/components/layout/auth-page-layout";
import { Button } from "@/components/ui/button";
import { FieldError } from "@/components/ui/field";
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
      const response = await apiFetch("/api/auth/oauth2/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ accept, oauth_query: oauthQuery }),
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
            <ul className="text-muted-foreground list-disc space-y-1 pl-5 text-sm">
              {scopes.map((scope) => (
                <li key={scope}>
                  {scope === "openrift:read"
                    ? m.auth_mcp_read()
                    : scope === "offline_access"
                      ? m.auth_mcp_offline()
                      : scope}
                </li>
              ))}
            </ul>
            <div className="flex justify-end gap-2">
              <Button variant="outline" disabled={pending} onClick={() => void decide(false)}>
                {m.auth_mcp_deny()}
              </Button>
              <Button disabled={pending} onClick={() => void decide(true)}>
                {m.auth_mcp_allow()}
              </Button>
            </div>
          </>
        )}
        {(error || !validRequest) && <FieldError role="alert">{m.auth_mcp_error()}</FieldError>}
      </AuthFormCard>
    </AuthPageLayout>
  );
}
