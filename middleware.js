export const config = { matcher: ["/((?!favicon.ico).*)"] };

export default function middleware(request) {
  const expectedUser = process.env.GUIDE_USER;
  const expectedPass = process.env.GUIDE_PASS;
  const header = request.headers.get("authorization") || "";
  if (expectedUser && expectedPass && header.startsWith("Basic ")) {
    let decoded = "";
    try { decoded = atob(header.slice(6)); } catch (e) {}
    const sep = decoded.indexOf(":");
    const user = decoded.slice(0, sep);
    const pass = decoded.slice(sep + 1);
    if (user === expectedUser && pass === expectedPass) return;
  }
  return new Response("This guide is not open yet. Enter the reader credentials to continue.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Biblically Literate AI"',
      "Content-Type": "text/plain"
    }
  });
}
