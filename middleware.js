export const config = { matcher: ["/((?!favicon.ico).*)"] };

const DAY = 1000 * 60 * 60 * 24;
const COOKIE = "bla_reader";

export default async function middleware(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/join" && request.method === "POST") {
    return join(request, url);
  }

  const authed = await hasValidCookie(request);

  if (path === "/" || path === "/index.html") {
    if (authed) return Response.redirect(new URL("/guide", request.url), 302);
    return; // serve the public gate page
  }

  if (authed) return; // serve protected content

  const back = "/?next=" + encodeURIComponent(path);
  return Response.redirect(new URL(back, request.url), 302);
}

async function join(request, url) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return new Response("Gate not configured", { status: 500 });

  let form;
  try {
    form = await request.formData();
  } catch (e) {
    return back(url, "Something went wrong reading the form. Try again.");
  }
  const user = String(form.get("username") || "").trim();
  const pass = String(form.get("password") || "");
  const next = String(form.get("next") || "/guide");

  if (!/^[A-Za-z0-9._-]{3,32}$/.test(user)) {
    return back(url, "Username: 3-32 characters, letters, numbers, dots or dashes.");
  }
  if (pass.length < 8) {
    return back(url, "Password needs at least 8 characters.");
  }

  const exp = Date.now() + 90 * DAY;
  const payload = btoa(user + "|" + exp);
  const sig = await hmac(secret, payload);
  console.log("reader account created:", user);

  const dest = next.startsWith("/") && !next.startsWith("//") ? next : "/guide";
  return new Response(null, {
    status: 303,
    headers: {
      "Location": new URL(dest, url).toString(),
      "Set-Cookie": COOKIE + "=" + encodeURIComponent(payload + "." + sig) +
        "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + (90 * 24 * 60 * 60)
    }
  });
}

function back(url, message) {
  return new Response(null, {
    status: 303,
    headers: { "Location": new URL("/?e=" + encodeURIComponent(message), url).toString() }
  });
}

async function hasValidCookie(request) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return false;
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  if (!m) return false;
  const token = decodeURIComponent(m[1]);
  const dot = token.lastIndexOf(".");
  if (dot < 1) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await hmac(secret, payload);
  if (expected !== sig) return false;
  try {
    const parts = atob(payload).split("|");
    return Number(parts[1]) > Date.now();
  } catch (e) {
    return false;
  }
}

async function hmac(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const buf = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  let out = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return btoa(out).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
