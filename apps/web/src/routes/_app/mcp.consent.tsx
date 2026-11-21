import { createFileRoute } from "@tanstack/react-router";

import { seoHead } from "@/lib/seo";
import { getSiteUrl } from "@/lib/site-config";

export const Route = createFileRoute("/_app/mcp/consent")({
  head: () =>
    seoHead({
      siteUrl: getSiteUrl(),
      title: "Connect to OpenRift",
      description: "Review an application's requested access to your OpenRift account.",
      path: "/mcp/consent",
      noIndex: true,
    }),
});
