import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

type CookieToSet = {
  name: string;
  value: string;
  options?: Parameters<NextResponse["cookies"]["set"]>[2];
};

export async function updateSession(request: NextRequest) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  let supabaseResponse = NextResponse.next({ request });

  if (!url || !key) {
    return supabaseResponse;
  }

  const supabase = createServerClient(url, key, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet: CookieToSet[]) {
        cookiesToSet.forEach(({ name, value }) => {
          request.cookies.set(name, value);
        });
        supabaseResponse = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => {
          supabaseResponse.cookies.set(name, value, options);
        });
      },
    },
  });

  // Refresh the auth token on every matched request (cookie-based session).
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;
  const isLogin = pathname === "/login";
  const isLoginApi = pathname === "/api/auth/login";
  const isPublic = isLogin || isLoginApi;

  if (!user && !isPublic) {
    if (pathname.startsWith("/api/")) {
      const unauthorized = NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 },
      );
      copyCookies(supabaseResponse, unauthorized);
      return unauthorized;
    }
    const redirectUrl = request.nextUrl.clone();
    redirectUrl.pathname = "/login";
    redirectUrl.search = "";
    const redirect = NextResponse.redirect(redirectUrl);
    copyCookies(supabaseResponse, redirect);
    return redirect;
  }

  if (user && isLogin) {
    const redirectUrl = request.nextUrl.clone();
    redirectUrl.pathname = "/";
    const redirect = NextResponse.redirect(redirectUrl);
    copyCookies(supabaseResponse, redirect);
    return redirect;
  }

  return supabaseResponse;
}

function copyCookies(from: NextResponse, to: NextResponse) {
  from.cookies.getAll().forEach((cookie) => {
    to.cookies.set(cookie);
  });
}
