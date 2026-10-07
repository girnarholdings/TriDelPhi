"use client";

import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: "https://example.ingest.sentry.io/1",
  integrations: [Sentry.replayIntegration()],
});

export function ChatWidget() {
  return <script src="https://widget.intercom.io/widget/abc123" />;
}
