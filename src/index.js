// src/index.js
import PostalMime from "postal-mime";

/**
 * Cloudflare Email Routing + Email Worker + Web Inbox
 * Features:
 * - Signup/Login/Logout
 * - Reset password (optional via Resend)
 * - Alias management with per-user limit
 * - Admin dashboard: list users, set alias limit, disable user
 * - Email handler: accept via catch-all, store if alias registered else reject
 */

const encoder = new TextEncoder();

// -------------------- Security/Hashing constants --------------------
const PBKDF2_MAX_ITERS = 100000; // Cloudflare Workers WebCrypto limit
const PBKDF2_MIN_ITERS = 10000;  // keep a sensible floor

// Cache (per isolate) whether DB has users.pass_iters column
let USERS_HAS_PASS_ITERS = null;

// -------------------- Response helpers --------------------
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "permissions-policy": "geolocation=(), microphone=(), camera=()",
      ...headers,
    },
  });
}

function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "permissions-policy": "geolocation=(), microphone=(), camera=()",
      ...headers,
    },
  });
}

function badRequest(msg) {
  return json({ ok: false, error: msg }, 400);
}
function unauthorized(msg = "Unauthorized") {
  return json({ ok: false, error: msg }, 401);
}
function forbidden(msg = "Forbidden") {
  return json({ ok: false, error: msg }, 403);
}
function notFound() {
  return json({ ok: false, error: "Not found" }, 404);
}

// -------------------- Utils --------------------
function safeInt(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function clampPbkdf2Iters(n) {
  const x = safeInt(n, PBKDF2_MAX_ITERS);
  return Math.min(PBKDF2_MAX_ITERS, Math.max(PBKDF2_MIN_ITERS, x));
}

function pbkdf2Iters(env) {
  // IMPORTANT: Workers WebCrypto max 100000, jadi kita clamp.
  // Env PBKDF2_ITERS boleh diset, tapi tetap tidak bisa > 100000.
  return clampPbkdf2Iters(env.PBKDF2_ITERS ?? PBKDF2_MAX_ITERS);
}

function base64Url(bytes) {
  // small arrays only (we only use for salts/tokens/hashes) -> safe
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(b64url) {
  const b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Base64Url(inputBytes) {
  const digest = await crypto.subtle.digest("SHA-256", inputBytes);
  return base64Url(new Uint8Array(digest));
}

async function pbkdf2HashBase64Url(password, saltBytes, iterations) {
  // Fail-fast bila someone tries to pass > max
  const it = safeInt(iterations, 0);
  if (it > PBKDF2_MAX_ITERS) {
    const err = new Error(
      `PBKDF2 iterations too high for Workers (max ${PBKDF2_MAX_ITERS}, got ${it}).`
    );
    err.name = "NotSupportedError";
    throw err;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: it,
    },
    keyMaterial,
    256
  );

  return base64Url(new Uint8Array(bits));
}

function getCookie(request, name) {
  const cookie = request.headers.get("cookie") || "";
  const parts = cookie.split(";").map((p) => p.trim());
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}

function setCookieHeader(name, value, opts = {}) {
  const {
    httpOnly = true,
    secure = true,
    sameSite = "Lax",
    path = "/",
    maxAge,
  } = opts;

  let c = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;
  if (httpOnly) c += "; HttpOnly";
  if (secure) c += "; Secure";
  if (typeof maxAge === "number") c += `; Max-Age=${maxAge}`;
  return c;
}

async function readJson(request) {
  try {
    const ct = request.headers.get("content-type") || "";
    if (!ct.toLowerCase().includes("application/json")) return null;
    return await request.json();
  } catch {
    return null;
  }
}

function validLocalPart(local) {
  // simple + aman: huruf angka . _ + - (1..64)
  return /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(local);
}

async function usersHasPassIters(env) {
  if (USERS_HAS_PASS_ITERS !== null) return USERS_HAS_PASS_ITERS;

  try {
    const res = await env.DB.prepare(`PRAGMA table_info(users)`).all();
    USERS_HAS_PASS_ITERS = (res.results || []).some((r) => r?.name === "pass_iters");
  } catch {
    USERS_HAS_PASS_ITERS = false;
  }
  return USERS_HAS_PASS_ITERS;
}

// -------------------- UI: Brand + Template --------------------
const FAVICON_DATA = encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#7dd3fc"/>
      <stop offset="1" stop-color="#6366f1"/>
    </linearGradient>
  </defs>
  <rect x="6" y="6" width="52" height="52" rx="12" fill="url(#g)"/>
  <text x="32" y="40" text-anchor="middle" font-size="26" font-family="Arial" fill="#0b0f14">OL</text>
</svg>
`);

function pageTemplate(title, body, extraHead = "") {
  // Note: keep CSP permissive for inline script/style (single-file UI).
  return `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${title}</title>
  <meta name="theme-color" content="#0b0f14">
  <link rel="icon" href="data:image/svg+xml,${FAVICON_DATA}">
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    base-uri 'none';
    object-src 'none';
    form-action 'self';
    frame-ancestors 'none';
    img-src 'self' data: https:;
    style-src 'self' 'unsafe-inline';
    script-src 'self' 'unsafe-inline';
    connect-src 'self';
    frame-src 'self';
  ">
  ${extraHead}
  <style>
    :root{
      --bg:#070a10;
      --card:#0f172a;
      --card2:#0b1220;
      --border:rgba(34,49,74,.92);
      --text:#e6edf3;
      --muted:#93a4b8;
      --brand1:#7dd3fc;
      --brand2:#6366f1;
      --danger:#ef4444;
      --shadow: 0 18px 45px rgba(0,0,0,.38);
      --radius: 18px;
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      margin:0;
      color:var(--text);
      background:
        radial-gradient(1200px 680px at 15% -10%, rgba(125,211,252,.16), transparent 60%),
        radial-gradient(900px 560px at 92% 0%, rgba(99,102,241,.14), transparent 55%),
        radial-gradient(800px 560px at 35% 120%, rgba(125,211,252,.08), transparent 55%),
        var(--bg);
    }
    a{color:var(--brand1);text-decoration:none}
    a:hover{text-decoration:underline; opacity:.92}

    /* Containers */
    .wrap{max-width:980px;margin:0 auto;padding:18px}
    .authWrap{
      min-height:100%;
      display:flex;
      align-items:center;
      justify-content:center;
      padding:16px;
    }
    .authShell{
      width:100%;
      max-width:560px;
      border-radius:22px;
      border:1px solid var(--border);
      background: linear-gradient(180deg, rgba(255,255,255,.04), transparent 45%), rgba(15,23,42,.92);
      box-shadow: var(--shadow);
      overflow:hidden;
    }

    /* Brand block (sesuai layout ASCII kamu) */
    .authTop{
      padding:18px 18px 14px;
      display:flex;
      flex-direction:column;
      gap:10px;
      align-items:center;
      text-align:center;
    }
    .logoBox{
      width:78px;height:62px;
      border-radius:16px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.03);
      display:flex;align-items:center;justify-content:center;
      position:relative;
    }
    .logoBox::before{
      content:"";
      position:absolute; inset:10px;
      border-radius:12px;
      background: linear-gradient(135deg, rgba(125,211,252,.26), rgba(99,102,241,.18));
      border:1px solid rgba(125,211,252,.18);
    }
    .logoText{
      position:relative;
      font-weight:900;
      letter-spacing:.6px;
      font-size:22px;
      color: var(--text);
      text-shadow: 0 8px 22px rgba(0,0,0,.45);
    }
    .orgName{font-weight:900; font-size:20px; letter-spacing:.2px}
    .portalName{color:var(--muted); font-size:13.5px; margin-top:-4px}
    .pill{
      display:inline-flex;align-items:center;gap:6px;
      padding:6px 10px;border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.03);
      color:var(--muted);
      font-size:12px;
    }

    .hr{border:0;border-top:1px solid var(--border);margin:0}

    /* Auth card area */
    .authCard{
      padding:16px 18px 18px;
    }
    .authTitleRow{
      display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;
      margin-bottom:10px;
    }
    .authTitle{font-weight:800}
    .authSub{color:var(--muted); font-size:13px; margin-top:4px}

    /* Shared UI */
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.035), transparent 40%), rgba(15,23,42,.92);
      border:1px solid var(--border);
      border-radius:var(--radius);
      padding:16px;
      margin:12px 0;
      box-shadow: 0 10px 30px rgba(0,0,0,.24);
      overflow:hidden;
    }

    label{display:block;margin-bottom:6px;color:var(--muted);font-size:13px}
    input,select,textarea{
      width:100%;
      padding:12px 12px;
      border-radius:14px;
      border:1px solid var(--border);
      background: rgba(11,18,32,.92);
      color:var(--text);
      outline:none;
      font-size:15px;
    }
    input::placeholder{color: rgba(147,164,184,.65)}
    input:focus,select:focus,textarea:focus{
      border-color: rgba(125,211,252,.75);
      box-shadow: 0 0 0 4px rgba(125,211,252,.12);
    }
    button{
      padding:11px 13px;
      border-radius:14px;
      border:1px solid var(--border);
      background: rgba(125,211,252,.12);
      color:var(--text);
      cursor:pointer;
      transition: transform .06s ease, background .15s ease, border-color .15s ease;
      white-space:nowrap;
      font-weight:650;
    }
    button:hover{background: rgba(125,211,252,.18); border-color: rgba(125,211,252,.28)}
    button:active{transform: translateY(1px)}
    .btn-primary{
      background: linear-gradient(135deg, rgba(125,211,252,.32), rgba(99,102,241,.20));
      border-color: rgba(125,211,252,.35);
    }
    .btn-ghost{background: rgba(255,255,255,.03)}
    .danger{
      border-color: rgba(239,68,68,.46);
      background: rgba(239,68,68,.10);
    }
    .danger:hover{background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.56)}

    .muted{color:var(--muted)}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .split{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start}
    .listItem{
      padding:10px 0;
      border-bottom:1px solid var(--border);
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      flex-wrap:wrap;
    }
    pre{margin:10px 0 0;white-space:pre-wrap;word-break:break-word; font-size:13px; line-height:1.35}

    .kbd{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      padding:2px 8px;
      border-radius:999px;
      border:1px solid var(--border);
      background: rgba(255,255,255,.03);
      color: var(--muted);
    }

    /* App header */
    .hdr{
      display:flex;justify-content:space-between;align-items:center;
      gap:14px; padding:10px 0 4px;
    }
    .brandInline{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
    .brandMiniLogo{
      width:42px;height:36px;border-radius:12px;border:1px solid var(--border);
      display:flex;align-items:center;justify-content:center;
      background: rgba(255,255,255,.03);
      position:relative;
      overflow:hidden;
    }
    .brandMiniLogo::before{
      content:""; position:absolute; inset:7px;
      border-radius:10px;
      background: linear-gradient(135deg, rgba(125,211,252,.22), rgba(99,102,241,.16));
      border:1px solid rgba(125,211,252,.14);
    }
    .brandMiniLogo span{position:relative;font-weight:900;font-size:14px;letter-spacing:.4px}
    .brandText{display:flex;flex-direction:column;line-height:1.05}
    .brandText .t1{font-weight:900}
    .brandText .t2{color:var(--muted);font-size:12.5px;margin-top:3px}
    .hdrRight{display:flex;gap:10px;align-items:center;flex-wrap:wrap}

    @media (max-width: 760px){
      .wrap{padding:14px}
      .hdr{flex-direction:column;align-items:flex-start}
      .row,.split{grid-template-columns:1fr}
    }
    @media (prefers-reduced-motion: reduce){
      button{transition:none}
      button:active{transform:none}
    }
  </style>
</head>
<body>
  ${body}
</body>
</html>`;
}

function appHeaderHtml({ badge, subtitle, rightHtml = "" }) {
  return `
  <header class="hdr">
    <div class="brandInline">
      <div class="brandMiniLogo"><span>OL</span></div>
      <div class="brandText">
        <div class="t1">Org_Lemah</div>
        <div class="t2">${subtitle || ""}</div>
      </div>
      ${badge ? `<span class="pill">${badge}</span>` : ""}
    </div>
    <div class="hdrRight">${rightHtml}</div>
  </header>`;
}

function authShellHtml({ badge, subtitle, title, rightLinkHtml = "", innerHtml }) {
  return `
  <div class="authWrap">
    <div class="authShell">
      <div class="authTop">
        <div class="logoBox" aria-label="Logo Org_Lemah">
          <div class="logoText">OL</div>
        </div>
        <div class="orgName">Org_Lemah</div>
        <div class="portalName">Mail Portal</div>
        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:center">
          ${badge ? `<span class="pill">${badge}</span>` : ""}
          ${rightLinkHtml || ""}
        </div>
        ${subtitle ? `<div class="authSub">${subtitle}</div>` : ""}
      </div>
      <hr class="hr" />
      <div class="authCard">
        <div class="authTitleRow">
          <div class="authTitle">${title || ""}</div>
        </div>
        ${innerHtml || ""}
      </div>
    </div>
  </div>`;
}

// -------------------- Pages --------------------
const PAGES = {
  login() {
    return pageTemplate(
      "Login",
      authShellHtml({
        badge: "Login",
        subtitle: "Masuk untuk kelola alias & inbox",
        title: "Masuk",
        rightLinkHtml: `<a class="pill" href="/signup">Buat akun</a>`,
        innerHtml: `
        <div class="row" style="margin-top:10px">
          <div>
            <label>Username / Email</label>
            <input id="id" placeholder="sipar / sipar@gmail.com" autocomplete="username" />
          </div>
          <div>
            <label>Password</label>
            <input id="pw" type="password" placeholder="••••••••" autocomplete="current-password" />
          </div>
        </div>

        <div style="margin-top:14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="login()">Login</button>
          <a href="/reset" class="muted">Lupa password?</a>
        </div>
        <pre id="out" class="muted"></pre>

        <script>
          async function readJsonOrText(r){
            try { return await r.json(); }
            catch {
              const t = await r.text().catch(()=> '');
              return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
            }
          }
          async function login(){
            const id = document.getElementById('id').value.trim();
            const pw = document.getElementById('pw').value;
            const out = document.getElementById('out');
            out.textContent = '...';
            const r = await fetch('/api/auth/login',{
              method:'POST',
              headers:{'content-type':'application/json'},
              body:JSON.stringify({id,pw})
            });
            const j = await readJsonOrText(r);
            if(j.ok){ location.href='/app'; return; }
            out.textContent = j.error || 'gagal';
          }
        </script>
        `,
      })
    );
  },

  signup(domain) {
    return pageTemplate(
      "Signup",
      authShellHtml({
        badge: "Signup",
        subtitle: `Alias email kamu nanti: <span class="kbd">nama@${domain}</span>`,
        title: "Buat akun",
        rightLinkHtml: `<a class="pill" href="/login">Login</a>`,
        innerHtml: `
        <div class="row" style="margin-top:10px">
          <div>
            <label>Username</label>
            <input id="u" placeholder="sipar" autocomplete="username" />
          </div>
          <div>
            <label>Email (untuk reset password)</label>
            <input id="e" placeholder="sipar@gmail.com" autocomplete="email" />
          </div>
        </div>

        <div style="margin-top:12px">
          <label>Password</label>
          <input id="pw" type="password" placeholder="minimal 8 karakter" autocomplete="new-password" />
          <div class="muted" style="margin-top:8px">
            Gunakan password yang kuat agar akun aman.
          </div>
        </div>

        <div style="margin-top:14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
          <button class="btn-primary" onclick="signup()">Buat Akun</button>
        </div>
        <pre id="out" class="muted"></pre>

        <script>
          async function readJsonOrText(r){
            try { return await r.json(); }
            catch {
              const t = await r.text().catch(()=> '');
              return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
            }
          }
          async function signup(){
            const username = document.getElementById('u').value.trim();
            const email = document.getElementById('e').value.trim();
            const pw = document.getElementById('pw').value;
            const out = document.getElementById('out');
            out.textContent = '...';
            const r = await fetch('/api/auth/signup',{
              method:'POST',
              headers:{'content-type':'application/json'},
              body:JSON.stringify({username,email,pw})
            });
            const j = await readJsonOrText(r);
            if(j.ok){ location.href='/app'; return; }
            out.textContent = j.error || 'gagal';
          }
        </script>
        `,
      })
    );
  },

  reset() {
    return pageTemplate(
      "Reset Password",
      authShellHtml({
        badge: "Reset",
        subtitle: "Minta token reset atau set password baru",
        title: "Reset Password",
        rightLinkHtml: `<a class="pill" href="/login">Login</a>`,
        innerHtml: `
        <div class="card" style="margin:10px 0 0">
          <label>Email akun</label>
          <input id="e" placeholder="sipar@gmail.com" autocomplete="email" />
          <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
            <button class="btn-primary" onclick="reqReset()">Kirim token</button>
          </div>
          <pre id="out" class="muted"></pre>
        </div>

        <div class="card">
          <div class="muted">Punya token?</div>
          <div class="row" style="margin-top:10px">
            <div>
              <label>Token</label>
              <input id="t" placeholder="token dari email" />
            </div>
            <div>
              <label>Password baru</label>
              <input id="npw" type="password" placeholder="••••••••" autocomplete="new-password" />
            </div>
          </div>
          <div style="margin-top:12px">
            <button class="btn-primary" onclick="confirmReset()">Set password</button>
          </div>
          <pre id="out2" class="muted"></pre>
        </div>

        <script>
          async function readJsonOrText(r){
            try { return await r.json(); }
            catch {
              const t = await r.text().catch(()=> '');
              return { ok:false, error: 'Server returned non-JSON ('+r.status+'). ' + (t ? t.slice(0,200) : '') };
            }
          }
          async function reqReset(){
            const email = document.getElementById('e').value.trim();
            const out = document.getElementById('out');
            out.textContent = '...';
            const r = await fetch('/api/auth/reset/request',{
              method:'POST',
              headers:{'content-type':'application/json'},
              body:JSON.stringify({email})
            });
            const j = await readJsonOrText(r);
            out.textContent = j.ok ? 'Jika email terdaftar, token dikirim.' : (j.error || 'gagal');
          }
          async function confirmReset(){
            const token = document.getElementById('t').value.trim();
            const newPw = document.getElementById('npw').value;
            const out = document.getElementById('out2');
            out.textContent = '...';
            const r = await fetch('/api/auth/reset/confirm',{
              method:'POST',
              headers:{'content-type':'application/json'},
              body:JSON.stringify({token,newPw})
            });
            const j = await readJsonOrText(r);
            out.textContent = j.ok ? 'Password diubah. Silakan login.' : (j.error || 'gagal');
          }
        </script>
        `,
      })
    );
  },

  app(domain) {
    return pageTemplate(
      "Inbox",
      `
      <div class="wrap">
        ${appHeaderHtml({
          badge: "Inbox",
          subtitle: "Kelola alias & baca email masuk",
          rightHtml: `
            <a href="/admin" id="adminLink" class="pill" style="display:none">Admin</a>
            <button class="danger" onclick="logout()">Logout</button>
          `,
        })}

        <div class="card">
          <div class="row">
            <div>
              <div class="muted">Akun</div>
              <div id="me">...</div>
            </div>
            <div>
              <div class="muted">Buat alias baru (<b>@${domain}</b>)</div>
              <div class="row" style="grid-template-columns:1fr auto;gap:10px;margin-top:8px">
                <input id="alias" placeholder="contoh: sipar" />
                <button class="btn-primary" onclick="createAlias()">Create</button>
              </div>
              <div id="aliasMsg" class="muted" style="margin-top:8px"></div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="split">
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
                <b>Aliases</b>
                <span class="muted" id="limitInfo"></span>
              </div>
              <div id="aliases" style="margin-top:6px"></div>
            </div>

            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
                <b>Emails</b>
                <button class="btn-ghost" onclick="loadEmails()" id="refreshBtn" disabled>Refresh</button>
              </div>
              <div class="muted" id="selAlias" style="margin-top:6px">Pilih alias…</div>
              <div id="emails" style="margin-top:6px"></div>
            </div>
          </div>
        </div>

        <div class="card" id="emailView" style="display:none"></div>
      </div>

      <script>
        let ME=null;
        let SELECTED=null;

        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) {
            const t = await r.text().catch(()=> '');
            throw new Error('Server returned non-JSON ('+r.status+'): ' + (t ? t.slice(0,200) : ''));
          }
          return j;
        }

        async function loadMe(){
          const j = await api('/api/me');
          if(!j.ok){ location.href='/login'; return; }
          ME=j.user;
          document.getElementById('me').innerHTML =
            '<div><b>'+esc(ME.username)+'</b> <span class="muted">('+esc(ME.email)+')</span></div>'+
            '<div class="muted">role: '+esc(ME.role)+'</div>';
          document.getElementById('limitInfo').textContent = 'limit: '+ME.alias_limit;
          if(ME.role==='admin') document.getElementById('adminLink').style.display='inline-flex';
        }

        async function loadAliases(){
          const j = await api('/api/aliases');
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box = document.getElementById('aliases');
          box.innerHTML='';
          if(j.aliases.length===0){
            box.innerHTML='<div class="muted">Belum ada alias.</div>';
            return;
          }
          for(const a of j.aliases){
            const div=document.createElement('div');
            div.className='listItem';
            const addr = a.local_part+'@${domain}';
            div.innerHTML =
              '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
                '<button class="btn-primary" onclick="selectAlias(\\''+a.local_part+'\\')">Open</button>'+
                '<span>'+esc(addr)+'</span>'+
                (a.disabled?'<span class="pill">disabled</span>':'')+
              '</div>'+
              '<div><button onclick="delAlias(\\''+a.local_part+'\\')" class="danger">Delete</button></div>';
            box.appendChild(div);
          }
        }

        async function selectAlias(local){
          SELECTED=local;
          document.getElementById('selAlias').textContent = 'Alias: '+local+'@${domain}';
          document.getElementById('refreshBtn').disabled=false;
          await loadEmails();
        }

        async function loadEmails(){
          if(!SELECTED) return;
          const j = await api('/api/emails?alias='+encodeURIComponent(SELECTED));
          if(!j.ok){ alert(j.error||'gagal'); return; }
          const box=document.getElementById('emails');
          box.innerHTML='';
          if(j.emails.length===0){
            box.innerHTML='<div class="muted">Belum ada email masuk.</div>';
            return;
          }
          for(const m of j.emails){
            const d=document.createElement('div');
            d.style.padding='10px 0';
            d.style.borderBottom='1px solid var(--border)';
            d.innerHTML =
              '<div><b>'+esc(m.subject||'(no subject)')+'</b></div>'+
              '<div class="muted">From: '+esc(m.from_addr)+'</div>'+
              '<div class="muted">'+esc(m.date||'')+'</div>'+
              '<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">'+
                '<button class="btn-primary" onclick="openEmail(\\''+m.id+'\\')">View</button>'+
                '<button onclick="delEmail(\\''+m.id+'\\')" class="danger">Delete</button>'+
              '</div>';
            box.appendChild(d);
          }
        }

        async function openEmail(id){
          const j = await api('/api/emails/'+encodeURIComponent(id));
          if(!j.ok){ alert(j.error||'gagal'); return; }

          const v=document.getElementById('emailView');
          v.style.display='block';
          v.innerHTML =
            '<div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap">'+
              '<b>'+esc(j.email.subject||'(no subject)')+'</b>'+
              '<button class="btn-ghost" onclick="document.getElementById(\\'emailView\\').style.display=\\'none\\'">Close</button>'+
            '</div>'+
            '<div class="muted" style="margin-top:6px">From: '+esc(j.email.from_addr)+'</div>'+
            '<div class="muted">To: '+esc(j.email.to_addr)+'</div>'+
            '<div class="muted">'+esc(j.email.date||'')+'</div>'+
            '<hr class="hr" style="margin:12px 0" />'+
            '<div id="msgBody"></div>';

          const body = document.getElementById('msgBody');

          if (j.email.html) {
            // Render HTML safely in sandboxed iframe (lebih aman dari XSS)
            const iframe = document.createElement('iframe');
            iframe.setAttribute('sandbox',''); // no scripts
            iframe.setAttribute('referrerpolicy','no-referrer');
            iframe.style.width = '100%';
            iframe.style.height = '65vh';
            iframe.style.border = '1px solid var(--border)';
            iframe.style.borderRadius = '14px';
            iframe.style.background = 'rgba(11,18,32,.92)';
            iframe.srcdoc = j.email.html;
            body.appendChild(iframe);

            const note = document.createElement('div');
            note.className = 'muted';
            note.style.marginTop = '8px';
            note.textContent = 'HTML ditampilkan dalam iframe sandbox.';
            body.appendChild(note);
          } else {
            const pre = document.createElement('pre');
            pre.style.whiteSpace = 'pre-wrap';
            pre.textContent = j.email.text || '';
            body.appendChild(pre);
          }

          v.scrollIntoView({behavior:'smooth'});
        }

        async function createAlias(){
          const local = document.getElementById('alias').value.trim().toLowerCase();
          const msg=document.getElementById('aliasMsg');
          msg.textContent='...';
          const j = await api('/api/aliases', {
            method:'POST',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({local})
          });
          msg.textContent = j.ok ? 'Alias dibuat.' : (j.error||'gagal');
          if(j.ok){
            document.getElementById('alias').value='';
            await loadMe();
            await loadAliases();
          }
        }

        async function delAlias(local){
          if(!confirm('Hapus alias '+local+'@${domain} ?')) return;
          const j = await api('/api/aliases/'+encodeURIComponent(local), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          if(SELECTED===local){
            SELECTED=null;
            document.getElementById('selAlias').textContent='Pilih alias…';
            document.getElementById('emails').innerHTML='';
            document.getElementById('refreshBtn').disabled=true;
          }
          document.getElementById('emailView').style.display='none';
          await loadMe();
          await loadAliases();
        }

        async function delEmail(id){
          if(!confirm('Hapus email ini?')) return;
          const j = await api('/api/emails/'+encodeURIComponent(id), {method:'DELETE'});
          if(!j.ok){ alert(j.error||'gagal'); return; }
          document.getElementById('emailView').style.display='none';
          await loadEmails();
        }

        async function logout(){
          await fetch('/api/auth/logout',{method:'POST'});
          location.href='/login';
        }

        (async ()=>{
          try{
            await loadMe();
            await loadAliases();
          }catch(e){
            alert(String(e && e.message ? e.message : e));
          }
        })();
      </script>
      `
    );
  },

  admin(domain) {
    return pageTemplate(
      "Admin",
      `
      <div class="wrap">
        ${appHeaderHtml({
          badge: "Admin",
          subtitle: "Kelola user & limit alias • @" + domain,
          rightHtml: `
            <a href="/app" class="pill">Inbox</a>
            <button class="danger" onclick="logout()">Logout</button>
          `,
        })}

        <div class="card">
          <b>Users</b>
          <div class="muted" style="margin-top:6px">Domain: <span class="kbd">@${domain}</span></div>
          <div id="users" style="margin-top:10px"></div>
        </div>
      </div>

      <script>
        function esc(s){return (s||'').replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));}

        async function api(path, opts){
          const r = await fetch(path, opts);
          const j = await r.json().catch(()=>null);
          if(!j) {
            const t = await r.text().catch(()=> '');
            throw new Error('Server returned non-JSON ('+r.status+'): ' + (t ? t.slice(0,200) : ''));
          }
          return j;
        }

        async function loadUsers(){
          const j = await api('/api/admin/users');
          if(!j.ok){
            alert(j.error||'gagal');
            if(j.error==='Forbidden') location.href='/app';
            return;
          }
          const box=document.getElementById('users');
          box.innerHTML='';
          for(const u of j.users){
            const div=document.createElement('div');
            div.className='listItem';
            div.innerHTML =
              '<div style="min-width:260px">'+
                '<div><b>'+esc(u.username)+'</b> <span class="muted">('+esc(u.email)+')</span></div>'+
                '<div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">'+
                  (u.role==='admin' ? '<span class="pill">admin</span>' : '<span class="pill">user</span>')+
                  (u.disabled?'<span class="pill">disabled</span>':'')+
                  '<span class="pill">created: '+esc(u.created_at)+'</span>'+
                '</div>'+
              '</div>'+
              '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
                '<input id="lim_'+esc(u.id)+'" value="'+u.alias_limit+'" style="width:120px" />'+
                '<button class="btn-primary" onclick="setLimit(\\''+esc(u.id)+'\\')">Set limit</button>'+
                '<button onclick="toggleUser(\\''+esc(u.id)+'\\','+(u.disabled?0:1)+')" class="danger">'+(u.disabled?'Enable':'Disable')+'</button>'+
              '</div>';
            box.appendChild(div);
          }
        }

        async function setLimit(id){
          const v = document.getElementById('lim_'+id).value;
          const lim = parseInt(v,10);
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {
            method:'PATCH',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({alias_limit:lim})
          });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function toggleUser(id, disabled){
          const j = await api('/api/admin/users/'+encodeURIComponent(id), {
            method:'PATCH',
            headers:{'content-type':'application/json'},
            body:JSON.stringify({disabled})
          });
          if(!j.ok){ alert(j.error||'gagal'); return; }
          await loadUsers();
        }

        async function logout(){
          await fetch('/api/auth/logout',{method:'POST'});
          location.href='/login';
        }

        loadUsers().catch(e=>alert(String(e && e.message ? e.message : e)));
      </script>
      `
    );
  },
};

// -------------------- Auth/session helpers --------------------
async function getUserBySession(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;

  const tokenHash = await sha256Base64Url(encoder.encode(token));
  const row = await env.DB.prepare(
    `SELECT s.user_id as user_id, u.id as id, u.username as username, u.email as email,
            u.role as role, u.alias_limit as alias_limit, u.disabled as disabled
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  )
    .bind(tokenHash, nowSec())
    .first();

  if (!row) return null;
  if (row.disabled) return null;

  return row;
}

async function createSession(env, userId, ttlSeconds) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64Url(tokenBytes);
  const tokenHash = await sha256Base64Url(encoder.encode(token));
  const t = nowSec();

  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?)`
  )
    .bind(tokenHash, userId, t + ttlSeconds, t)
    .run();

  return token;
}

async function destroySession(request, env) {
  const token = getCookie(request, "session");
  if (!token) return;

  const tokenHash = await sha256Base64Url(encoder.encode(token));
  await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`)
    .bind(tokenHash)
    .run();
}

async function cleanupExpired(env) {
  const t = nowSec();
  try {
    await env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).bind(t).run();
  } catch (e) {
    console.log("cleanup sessions error:", e?.message || String(e));
  }
  try {
    await env.DB.prepare(`DELETE FROM reset_tokens WHERE expires_at <= ?`).bind(t).run();
  } catch (e) {
    console.log("cleanup reset_tokens error:", e?.message || String(e));
  }
}

// -------------------- Reset email (optional Resend) --------------------
async function sendResetEmail(env, toEmail, token) {
  if (!env.RESEND_API_KEY) return;

  const base = env.APP_BASE_URL || "";
  const link = base ? `${base}/reset#token=${encodeURIComponent(token)}` : "";

  const subject = "Reset password";
  const bodyHtml = `
    <div style="font-family:Arial,sans-serif">
      <p>Permintaan reset password.</p>
      <p><b>Token:</b> ${token}</p>
      ${link ? `<p>Atau klik: <a href="${link}">${link}</a></p>` : ""}
      <p>Jika bukan kamu, abaikan email ini.</p>
    </div>
  `;

  const from = env.RESET_FROM || `no-reply@${env.DOMAIN}`;

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [toEmail],
      subject,
      html: bodyHtml,
    }),
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.log("Resend failed:", r.status, txt.slice(0, 300));
  }
}

// -------------------- Worker entry --------------------
export default {
  async fetch(request, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));

    const url = new URL(request.url);
    const path = url.pathname;
    const cookieSecure = url.protocol === "https:"; // dev-friendly

    // Pages
    if (request.method === "GET") {
      if (path === "/" || path === "/login") return html(PAGES.login());
      if (path === "/signup") return html(PAGES.signup(env.DOMAIN));
      if (path === "/reset") return html(PAGES.reset());
      if (path === "/app") return html(PAGES.app(env.DOMAIN));
      if (path === "/admin") return html(PAGES.admin(env.DOMAIN));
    }

    // API (dibungkus try/catch supaya gak pernah return HTML error -> "bad json")
    if (path.startsWith("/api/")) {
      try {
        // Auth
        if (path === "/api/auth/signup" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const username = String(body.username || "").trim().toLowerCase();
          const email = String(body.email || "").trim().toLowerCase();
          const pw = String(body.pw || "");

          if (!/^[a-z0-9_]{3,24}$/.test(username))
            return badRequest("Username 3-24, a-z0-9_");
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            return badRequest("Email tidak valid");
          if (pw.length < 8) return badRequest("Password minimal 8 karakter");

          const iters = pbkdf2Iters(env);

          const salt = crypto.getRandomValues(new Uint8Array(16));
          const pass_salt = base64Url(salt);
          const pass_hash = await pbkdf2HashBase64Url(pw, salt, iters);

          const t = nowSec();
          const id = crypto.randomUUID();

          // first user becomes admin
          const c = await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first();
          const count = Number(c?.c ?? 0);
          const role = count === 0 ? "admin" : "user";
          const aliasLimit = safeInt(env.DEFAULT_ALIAS_LIMIT, 3);

          try {
            const hasIters = await usersHasPassIters(env);
            if (hasIters) {
              await env.DB.prepare(
                `INSERT INTO users (id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
              )
                .bind(id, username, email, pass_salt, pass_hash, iters, role, aliasLimit, t)
                .run();
            } else {
              await env.DB.prepare(
                `INSERT INTO users (id, username, email, pass_salt, pass_hash, role, alias_limit, disabled, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
              )
                .bind(id, username, email, pass_salt, pass_hash, role, aliasLimit, t)
                .run();
            }
          } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toUpperCase().includes("UNIQUE"))
              return badRequest("Username/email sudah dipakai");
            console.log("signup db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, id, ttl);

          return json(
            { ok: true },
            200,
            { "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }) }
          );
        }

        if (path === "/api/auth/login" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const id = String(body.id || "").trim().toLowerCase(); // username or email
          const pw = String(body.pw || "");

          if (!id || !pw) return badRequest("Lengkapi data");

          const hasIters = await usersHasPassIters(env);

          const user = hasIters
            ? await env.DB.prepare(
                `SELECT id, username, email, pass_salt, pass_hash, pass_iters, role, alias_limit, disabled
                 FROM users WHERE username = ? OR email = ?`
              ).bind(id, id).first()
            : await env.DB.prepare(
                `SELECT id, username, email, pass_salt, pass_hash, role, alias_limit, disabled
                 FROM users WHERE username = ? OR email = ?`
              ).bind(id, id).first();

          if (!user || user.disabled) return unauthorized("Login gagal");

          const saltBytes = base64UrlToBytes(user.pass_salt);

          // If per-user iters exists, use it. Else rely on env (must be consistent).
          const iters = hasIters ? safeInt(user.pass_iters, pbkdf2Iters(env)) : pbkdf2Iters(env);

          if (iters > PBKDF2_MAX_ITERS) {
            return unauthorized("Hash password lama tidak didukung. Silakan reset password.");
          }

          let hash;
          try {
            hash = await pbkdf2HashBase64Url(pw, saltBytes, iters);
          } catch (e) {
            const name = e?.name || "";
            if (name === "NotSupportedError") {
              return unauthorized("Parameter hash tidak didukung. Silakan reset password.");
            }
            throw e;
          }

          if (hash !== user.pass_hash) return unauthorized("Login gagal");

          const ttl = safeInt(env.SESSION_TTL_SECONDS, 1209600);
          const token = await createSession(env, user.id, ttl);

          return json(
            { ok: true },
            200,
            { "set-cookie": setCookieHeader("session", token, { maxAge: ttl, secure: cookieSecure }) }
          );
        }

        if (path === "/api/auth/logout" && request.method === "POST") {
          await destroySession(request, env);
          return json(
            { ok: true },
            200,
            { "set-cookie": setCookieHeader("session", "", { maxAge: 0, secure: cookieSecure }) }
          );
        }

        if (path === "/api/auth/reset/request" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");
          const email = String(body.email || "").trim().toLowerCase();
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            return badRequest("Email tidak valid");

          const user = await env.DB.prepare(
            `SELECT id, disabled FROM users WHERE email = ?`
          )
            .bind(email)
            .first();

          // Selalu balas ok (anti user-enumeration)
          if (!user || user.disabled) return json({ ok: true });

          const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
          const token = base64Url(tokenBytes);
          const tokenHash = await sha256Base64Url(encoder.encode(token));
          const t = nowSec();
          const ttl = safeInt(env.RESET_TTL_SECONDS, 3600);

          await env.DB.prepare(
            `INSERT INTO reset_tokens (token_hash, user_id, expires_at, created_at)
             VALUES (?, ?, ?, ?)`
          )
            .bind(tokenHash, user.id, t + ttl, t)
            .run();

          ctx.waitUntil(sendResetEmail(env, email, token));
          return json({ ok: true });
        }

        if (path === "/api/auth/reset/confirm" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const token = String(body.token || "").trim();
          const newPw = String(body.newPw || "");

          if (!token) return badRequest("Token wajib");
          if (newPw.length < 8) return badRequest("Password minimal 8 karakter");

          const tokenHash = await sha256Base64Url(encoder.encode(token));
          const rt = await env.DB.prepare(
            `SELECT user_id, expires_at FROM reset_tokens WHERE token_hash = ?`
          )
            .bind(tokenHash)
            .first();

          if (!rt || rt.expires_at <= nowSec()) return badRequest("Token invalid/expired");

          const iters = pbkdf2Iters(env);
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const pass_salt = base64Url(salt);
          const pass_hash = await pbkdf2HashBase64Url(newPw, salt, iters);

          const hasIters = await usersHasPassIters(env);
          if (hasIters) {
            await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=?, pass_iters=? WHERE id=?`)
              .bind(pass_salt, pass_hash, iters, rt.user_id)
              .run();
          } else {
            await env.DB.prepare(`UPDATE users SET pass_salt=?, pass_hash=? WHERE id=?`)
              .bind(pass_salt, pass_hash, rt.user_id)
              .run();
          }

          await env.DB.prepare(`DELETE FROM reset_tokens WHERE token_hash=?`)
            .bind(tokenHash)
            .run();

          return json({ ok: true });
        }

        // Auth required below
        const me = await getUserBySession(request, env);
        if (!me) return unauthorized();

        if (path === "/api/me" && request.method === "GET") {
          return json({
            ok: true,
            user: {
              id: me.id,
              username: me.username,
              email: me.email,
              role: me.role,
              alias_limit: me.alias_limit,
            },
          });
        }

        // Aliases
        if (path === "/api/aliases" && request.method === "GET") {
          const rows = await env.DB.prepare(
            `SELECT local_part, disabled, created_at
             FROM aliases WHERE user_id = ? ORDER BY created_at DESC`
          )
            .bind(me.id)
            .all();

          return json({ ok: true, aliases: rows.results || [] });
        }

        if (path === "/api/aliases" && request.method === "POST") {
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const local = String(body.local || "").trim().toLowerCase();
          if (!validLocalPart(local)) return badRequest("Alias tidak valid (a-z0-9._+- max 64)");

          // enforce limit
          const cnt = await env.DB.prepare(
            `SELECT COUNT(*) as c FROM aliases WHERE user_id = ? AND disabled = 0`
          )
            .bind(me.id)
            .first();

          if ((Number(cnt?.c ?? 0)) >= me.alias_limit) return forbidden("Limit alias tercapai");

          const t = nowSec();
          try {
            await env.DB.prepare(
              `INSERT INTO aliases (local_part, user_id, disabled, created_at)
               VALUES (?, ?, 0, ?)`
            )
              .bind(local, me.id, t)
              .run();
          } catch (e) {
            const msg = String(e && e.message ? e.message : e);
            if (msg.toUpperCase().includes("UNIQUE")) return badRequest("Alias sudah dipakai");
            console.log("alias db error:", msg);
            return json({ ok: false, error: "DB error" }, 500);
          }

          return json({ ok: true });
        }

        if (path.startsWith("/api/aliases/") && request.method === "DELETE") {
          const local = decodeURIComponent(path.slice("/api/aliases/".length)).toLowerCase();
          if (!validLocalPart(local)) return badRequest("Alias invalid");

          const own = await env.DB.prepare(
            `SELECT local_part FROM aliases WHERE local_part = ? AND user_id = ?`
          )
            .bind(local, me.id)
            .first();

          if (!own) return notFound();

          await env.DB.prepare(`DELETE FROM aliases WHERE local_part = ? AND user_id = ?`)
            .bind(local, me.id)
            .run();

          return json({ ok: true });
        }

        // Emails
        if (path === "/api/emails" && request.method === "GET") {
          const alias = (url.searchParams.get("alias") || "").trim().toLowerCase();
          if (!alias || !validLocalPart(alias)) return badRequest("alias required");

          // check ownership
          const own = await env.DB.prepare(
            `SELECT local_part FROM aliases WHERE local_part = ? AND user_id = ? AND disabled = 0`
          )
            .bind(alias, me.id)
            .first();
          if (!own) return forbidden("Alias bukan milikmu / disabled");

          const rows = await env.DB.prepare(
            `SELECT id, from_addr, to_addr, subject, date, created_at
             FROM emails
             WHERE user_id = ? AND local_part = ?
             ORDER BY created_at DESC
             LIMIT 50`
          )
            .bind(me.id, alias)
            .all();

          return json({ ok: true, emails: rows.results || [] });
        }

        if (path.startsWith("/api/emails/") && request.method === "GET") {
          const id = decodeURIComponent(path.slice("/api/emails/".length));
          const row = await env.DB.prepare(
            `SELECT id, from_addr, to_addr, subject, date, text, html, raw_key, created_at
             FROM emails WHERE id = ? AND user_id = ?`
          )
            .bind(id, me.id)
            .first();

          if (!row) return notFound();
          return json({ ok: true, email: row });
        }

        if (path.startsWith("/api/emails/") && request.method === "DELETE") {
          const id = decodeURIComponent(path.slice("/api/emails/".length));
          const row = await env.DB.prepare(
            `SELECT raw_key FROM emails WHERE id = ? AND user_id = ?`
          )
            .bind(id, me.id)
            .first();
          if (!row) return notFound();

          await env.DB.prepare(`DELETE FROM emails WHERE id = ? AND user_id = ?`)
            .bind(id, me.id)
            .run();

          if (row.raw_key && env.MAIL_R2) {
            ctx.waitUntil(env.MAIL_R2.delete(row.raw_key));
          }

          return json({ ok: true });
        }

        // Admin endpoints
        if (path === "/api/admin/users" && request.method === "GET") {
          if (me.role !== "admin") return forbidden("Forbidden");

          const rows = await env.DB.prepare(
            `SELECT id, username, email, role, alias_limit, disabled, created_at
             FROM users ORDER BY created_at DESC LIMIT 200`
          ).all();

          const users = (rows.results || []).map((u) => ({
            ...u,
            created_at: new Date(u.created_at * 1000).toISOString(),
          }));

          return json({ ok: true, users });
        }

        if (path.startsWith("/api/admin/users/") && request.method === "PATCH") {
          if (me.role !== "admin") return forbidden("Forbidden");
          const userId = decodeURIComponent(path.slice("/api/admin/users/".length));
          const body = await readJson(request);
          if (!body) return badRequest("JSON required");

          const alias_limit =
            body.alias_limit !== undefined ? safeInt(body.alias_limit, NaN) : undefined;
          const disabled =
            body.disabled !== undefined ? safeInt(body.disabled, NaN) : undefined;

          if (
            alias_limit !== undefined &&
            (!Number.isFinite(alias_limit) || alias_limit < 0 || alias_limit > 1000)
          ) {
            return badRequest("alias_limit invalid");
          }
          if (disabled !== undefined && !(disabled === 0 || disabled === 1)) {
            return badRequest("disabled invalid");
          }

          const sets = [];
          const binds = [];
          if (alias_limit !== undefined) {
            sets.push("alias_limit = ?");
            binds.push(alias_limit);
          }
          if (disabled !== undefined) {
            sets.push("disabled = ?");
            binds.push(disabled);
          }
          if (sets.length === 0) return badRequest("No fields");

          binds.push(userId);

          await env.DB.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`)
            .bind(...binds)
            .run();

          return json({ ok: true });
        }

        return notFound();
      } catch (e) {
        console.log("API ERROR:", e && e.stack ? e.stack : e);
        return json({ ok: false, error: "Server error" }, 500);
      }
    }

    return notFound();
  },

  async email(message, env, ctx) {
    try {
      const domain = String(env.DOMAIN || "").toLowerCase();
      const to = String(message.to || "").toLowerCase();
      const [local, toDomain] = to.split("@");

      if (!local || !toDomain || toDomain !== domain) {
        message.setReject("Bad recipient");
        return;
      }

      // Lookup alias + user
      const row = await env.DB.prepare(
        `SELECT a.local_part as local_part, a.user_id as user_id, a.disabled as alias_disabled,
                u.disabled as user_disabled
         FROM aliases a
         JOIN users u ON u.id = a.user_id
         WHERE a.local_part = ?`
      )
        .bind(local)
        .first();

      if (!row || row.alias_disabled || row.user_disabled) {
        message.setReject("Unknown recipient");
        return;
      }

      const maxStore = safeInt(env.MAX_STORE_BYTES, 262144);
      if (message.rawSize && message.rawSize > maxStore) {
        message.setReject("Message too large");
        return;
      }

      const rawEmail = new Response(message.raw);
      const ab = await rawEmail.arrayBuffer();

      const parser = new PostalMime();
      const parsed = await parser.parse(ab);

      const id = crypto.randomUUID();
      const t = nowSec();

      const subject = parsed.subject || "";
      const date = parsed.date ? new Date(parsed.date).toISOString() : "";
      const fromAddr =
        (parsed.from && parsed.from.address) ? parsed.from.address : (message.from || "");
      const toAddr = message.to || "";

      const maxTextChars = safeInt(env.MAX_TEXT_CHARS, 200000);
      const text = (parsed.text || "").slice(0, maxTextChars);
      const htmlPart = (parsed.html || "").slice(0, maxTextChars);

      let raw_key = null;
      if (env.MAIL_R2) {
        raw_key = `emails/${id}.eml`;
        ctx.waitUntil(
          env.MAIL_R2.put(raw_key, ab, {
            httpMetadata: { contentType: "message/rfc822" },
          })
        );
      }

      await env.DB.prepare(
        `INSERT INTO emails
         (id, local_part, user_id, from_addr, to_addr, subject, date, text, html, raw_key, size, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          id,
          row.local_part,
          row.user_id,
          fromAddr,
          toAddr,
          subject,
          date,
          text,
          htmlPart,
          raw_key,
          ab.byteLength || (message.rawSize || 0),
          t
        )
        .run();
    } catch (e) {
      console.log("email handler error:", e && e.stack ? e.stack : e);
      message.setReject("Temporary processing error");
    }
  },
};
