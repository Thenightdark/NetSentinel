import { NextRequest, NextResponse } from "next/server";

const SESSION_COOKIE = "netsentinel_session";

export async function proxy(request: NextRequest) {
  if (request.nextUrl.pathname === "/login") return NextResponse.next();
  const session = request.cookies.get(SESSION_COOKIE);
  if (session) {
    try {
      const apiUrl = process.env.INTERNAL_API_URL ?? "http://localhost:8000";
      const response = await fetch(`${apiUrl}/api/auth/me`, {
        cache: "no-store",
        headers: { Cookie: `${SESSION_COOKIE}=${session.value}` },
      });
      if (response.ok) return NextResponse.next();
    } catch {
      // Fail closed when the API cannot validate the dashboard session.
    }
  }

  const loginUrl = new URL("/login", request.url);
  loginUrl.searchParams.set("returnTo", `${request.nextUrl.pathname}${request.nextUrl.search}`);
  const response = NextResponse.redirect(loginUrl);
  response.cookies.delete(SESSION_COOKIE);
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
