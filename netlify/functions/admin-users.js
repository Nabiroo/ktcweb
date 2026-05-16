// netlify/functions/admin-users.js
// Proxies Netlify Identity admin operations so the service token
// is never exposed to the browser.
// Environment variable required: NETLIFY_IDENTITY_SERVICE_TOKEN
//   (set in Netlify dashboard → Site settings → Environment variables)

const https = require("https");

const IDENTITY_URL = process.env.URL
  ? `${process.env.URL}/.netlify/identity`
  : null;

const SERVICE_TOKEN = process.env.NETLIFY_IDENTITY_SERVICE_TOKEN;

function identityRequest(method, path, body, adminToken) {
  return new Promise((resolve, reject) => {
    if (!IDENTITY_URL) return reject(new Error("URL env var not set"));

    const url = new URL(IDENTITY_URL + path);
    const bodyStr = body ? JSON.stringify(body) : null;

    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken || SERVICE_TOKEN}`,
        ...(bodyStr ? { "Content-Length": Buffer.byteLength(bodyStr) } : {}),
      },
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on("error", reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

// Verify the caller is an authenticated admin
async function verifyAdmin(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  const result = await identityRequest("GET", "/user", null, token);
  if (result.status !== 200) return null;
  const user = result.body;
  const isAdmin =
    user.app_metadata?.roles?.includes("admin") ||
    user.app_metadata?.is_admin === true;
  return isAdmin ? user : null;
}

exports.handler = async (event) => {
  const headers = {
    "Access-Control-Allow-Origin": process.env.URL || "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }

  // All non-OPTIONS requests require a valid admin JWT
  const admin = await verifyAdmin(event.headers.authorization);
  if (!admin) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: "Forbidden: admin access required" }),
    };
  }

  try {
    const { action, email, userId, role } = JSON.parse(event.body || "{}");

    // ── List all users ──────────────────────────────────────────
    if (action === "list") {
      const result = await identityRequest("GET", "/admin/users", null);
      return { statusCode: result.status, headers, body: JSON.stringify(result.body) };
    }

    // ── Invite a new user by email ──────────────────────────────
    if (action === "invite") {
      if (!email) return { statusCode: 400, headers, body: JSON.stringify({ error: "email required" }) };
      const result = await identityRequest("POST", "/admin/users", { email, send_email: true });
      return { statusCode: result.status, headers, body: JSON.stringify(result.body) };
    }

    // ── Update a user's role ────────────────────────────────────
    if (action === "set-role") {
      if (!userId || !role) return { statusCode: 400, headers, body: JSON.stringify({ error: "userId and role required" }) };
      const result = await identityRequest("PUT", `/admin/users/${userId}`, {
        app_metadata: { roles: [role] },
      });
      return { statusCode: result.status, headers, body: JSON.stringify(result.body) };
    }

    // ── Delete a user ───────────────────────────────────────────
    if (action === "delete") {
      if (!userId) return { statusCode: 400, headers, body: JSON.stringify({ error: "userId required" }) };
      const result = await identityRequest("DELETE", `/admin/users/${userId}`, null);
      return { statusCode: result.status, headers, body: JSON.stringify({ ok: true }) };
    }

    return { statusCode: 400, headers, body: JSON.stringify({ error: "Unknown action" }) };
  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: "Internal server error" }) };
  }
};
