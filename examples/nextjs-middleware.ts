// Sésamo reference client for Next.js (App Router) — middleware.ts
//
// Drop this at the project root. It forwards the session cookie to
// Sésamo's /v1/introspect endpoint and gates protected routes. No SDK,
// no JWT parsing — just one HTTP call per request (p99 ~4ms locally).
//
// Env:
//   SESAMO_URL=http://localhost:7777
//   SESAMO_SERVICE_TOKEN=<your SESAMO_SERVICE_TOKEN>

import { NextRequest, NextResponse } from "next/server";

const SESAMO_URL = process.env.SESAMO_URL!;
const SERVICE_TOKEN = process.env.SESAMO_SERVICE_TOKEN!;

export async function middleware(req: NextRequest) {
  const sid = req.cookies.get("sid")?.value;
  if (!sid) return NextResponse.redirect(new URL("/login", req.url));

  const res = await fetch(`${SESAMO_URL}/v1/introspect`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SERVICE_TOKEN}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ token: sid }),
    cache: "no-store",
  });

  const session = await res.json();
  if (!session.active) return NextResponse.redirect(new URL("/login", req.url));

  // Pass identity to downstream route handlers via request headers.
  const headers = new Headers(req.headers);
  headers.set("x-user-id", session.user_id);
  headers.set("x-user-email", session.email);
  return NextResponse.next({ request: { headers } });
}

// Protect everything except auth + static assets.
export const config = {
  matcher: ["/((?!login|_next|favicon.ico|api/public).*)"],
};
