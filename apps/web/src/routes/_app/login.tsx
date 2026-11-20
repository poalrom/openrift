import { createFileRoute } from "@tanstack/react-router";

import { redirectSignedIn } from "@/lib/auth-session";
import { randomEmailPlaceholder } from "@/lib/placeholders";
import { authSearchSchema } from "@/lib/route-search";
import { seoHead } from "@/lib/seo";
import { getSiteUrl } from "@/lib/site-config";

export const Route = createFileRoute("/_app/login")({
  validateSearch: (search: Record<string, unknown>) => ({ ...search, ...authSearchSchema(search) }),
  beforeLoad: async (context) => {
    // A signed OAuth request may explicitly require the user to sign in again.
    const search: Record<string, unknown> = context.search;
    if (typeof search.sig !== "string" || typeof search.client_id !== "string") {
      await redirectSignedIn(context);
    }
  },
  head: () =>
    seoHead({
      siteUrl: getSiteUrl(),
      title: "Log In",
      description: "Sign in to your OpenRift account.",
      path: "/login",
      noIndex: true,
    }),
  loader: () => ({ emailPlaceholder: randomEmailPlaceholder() }),
});
