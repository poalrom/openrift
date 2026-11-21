import { createLazyFileRoute } from "@tanstack/react-router";

import { McpConsentPage } from "@/features/account/components/mcp-consent-page";

export const Route = createLazyFileRoute("/_app/mcp/consent")({ component: McpConsentPage });
