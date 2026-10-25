// 게재나라 서버 (Cloudflare Worker + D1)
// - 회원(아이디·비번) / 로그인 출석 포인트 / 포인트 장부
// - 참여자 수집기가 올린 게재면 접수함(중앙 PC가 가져가면 바로 지움)
// - 오래된 게재면 고화질 원본 요청(포인트 차감) 대기열
// 비밀값(비번 해시용 pepper, 중앙 PC 전용 관리 키)은 코드에 없고, 처음 실행 때 서버가 스스로 만들어 DB에 보관
// 포인트는 '후불': 참여자가 올린 게재면을 중앙 PC가 확인해서 기존에 없던 새 광고일 때만 지급

const ORIGINS = ["https://ads.jintar.co.kr", "http://localhost:8765"];
const POINTS = { login: 10, new_ad: 10, od_cost: 30, signup: 30 };
const LIMITS = { uploadsPerDay: 300, fileMax: 1_600_000, filesMax: 12, bodyMax: 12_000_000, signupPerHour: 5 };
const PLACEMENTS = ["youtube_instream", "youtube_infeed", "youtube_mobile_instream", "youtube_mobile_infeed", "youtube_mobile_shorts"];

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const kstDay = () => new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);
const now = () => new Date().toISOString();

async function pwHash(pw, salt, pepper) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw + pepper), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 20000 }, key, 256);
  return hex(bits);
}

// 테이블은 서버가 처음 실행될 때 스스로 만듦
const SCHEMA = `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, salt TEXT NOT NULL, points INTEGER NOT NULL DEFAULT 0, created TEXT, last_login_day TEXT, banned INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT, expires TEXT);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, delta INTEGER, reason TEXT, ref TEXT, at TEXT);
CREATE INDEX IF NOT EXISTS ledger_user ON ledger(user_id, id);
CREATE TABLE IF NOT EXISTS inbox_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ad_key TEXT UNIQUE, placement TEXT, meta TEXT, status TEXT, note TEXT, central_ad_id INTEGER, day TEXT, created TEXT, points INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS inbox_status ON inbox_log(status, id);
CREATE INDEX IF NOT EXISTS inbox_user_day ON inbox_log(user_id, day);
CREATE TABLE IF NOT EXISTS inbox_files (id INTEGER PRIMARY KEY AUTOINCREMENT, inbox_id INTEGER, name TEXT, data BLOB);
CREATE INDEX IF NOT EXISTS inbox_files_inbox ON inbox_files(inbox_id);
CREATE TABLE IF NOT EXISTS od_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ad_id INTEGER, status TEXT, created TEXT);
CREATE INDEX IF NOT EXISTS od_status ON od_requests(status, id);
CREATE TABLE IF NOT EXISTS signup_rl (ip_hash TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS sightings (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, ad_key TEXT, placement TEXT, context TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT);`;
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  for (const stmt of SCHEMA.split(";").map((x) => x.trim()).filter(Boolean)) await db.prepare(stmt).run();
  schemaReady = true;
}

async function secrets(db) {
  let r = await db.prepare("SELECT v FROM config WHERE k = 'pepper'").first();
  if (!r) { await db.prepare("INSERT OR IGNORE INTO config (k, v) VALUES ('pepper', ?)").bind(rand(32)).run(); r = await db.prepare("SELECT v FROM config WHERE k = 'pepper'").first(); }
  const a = await db.prepare("SELECT v FROM config WHERE k = 'admin_hash'").first();
  return { PEPPER: r.v, ADMIN_HASH: a ? a.v : null };
}

function cors(req) {
  const o = req.headers.get("Origin") || "";
  return {
    "Access-Control-Allow-Origin": ORIGINS.includes(o) ? o : ORIGINS[0],
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}
const J = (req, body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...cors(req) } });
const E = (req, msg, status = 400) => J(req, { ok: false, error: msg }, status);

async function addPoints(db, user, delta, reason, ref = "") {
  await db.batch([
    db.prepare("UPDATE users SET points = points + ? WHERE id = ?").bind(delta, user),
    db.prepare("INSERT INTO ledger (user_id, delta, reason, ref, at) VALUES (?,?,?,?,?)").bind(user, delta, reason, String(ref), now()),
  ]);
}

async function newSession(db, user, kind) {
  const token = rand(32);
  const days = kind === "agent" ? 90 : 30;
  await db.prepare("INSERT INTO sessions (token_hash, user_id, kind, expires) VALUES (?,?,?,?)")
    .bind(await sha256(token), user, kind, new Date(Date.now() + days * 864e5).toISOString()).run();
  return token;
}

async function auth(req, db) {
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  const row = await db.prepare("SELECT s.user_id, s.kind, s.expires, u.points, u.banned FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?")
    .bind(await sha256(h.slice(7))).first();
  if (!row || row.expires < now() || row.banned) return null;
  return row;
}

async function loginBonus(db, user) {
  const day = kstDay();
  const r = await db.prepare("UPDATE users SET last_login_day = ? WHERE id = ? AND (last_login_day IS NULL OR last_login_day <> ?)").bind(day, user, day).run();
  if (r.meta.changes) { await addPoints(db, user, POINTS.login, "login", day); return POINTS.login; }
  return 0;
}

async function me(db, user) {
  const u = await db.prepare("SELECT id, points, created FROM users WHERE id = ?").bind(user).first();
  const c = await db.prepare("SELECT COUNT(*) n FROM inbox_log WHERE user_id = ? AND status = 'accepted'").bind(user).first();
  const recent = await db.prepare("SELECT delta, reason, at FROM ledger WHERE user_id = ? ORDER BY id DESC LIMIT 20").bind(user).all();
  return { id: u.id, points: u.points, created: u.created, accepted: c.n, ledger: recent.results };
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(req) });
    const url = new URL(req.url);
    const p = url.pathname;
    const db = env.DB;
    try {
      await ensureSchema(db);
      const sec = await secrets(db);
      env = { ...env, PEPPER: sec.PEPPER };
      // 중앙 PC 관리 키 최초 발급(딱 한 번만 가능 — 이후엔 거부)
      if (p === "/api/admin/bootstrap" && req.method === "POST") {
        if (sec.ADMIN_HASH) return E(req, "이미 발급됨", 403);
        const t = rand(32);
        const r = await db.prepare("INSERT OR IGNORE INTO config (k, v) VALUES ('admin_hash', ?)").bind(await sha256(t)).run();
        if (!r.meta.changes) return E(req, "이미 발급됨", 403);
        return J(req, { ok: true, admin_token: t });
      }
      // ── 회원 ────────────────────────────────
      if (p === "/api/signup" && req.method === "POST") {
        const { id, pw } = await req.json();
        if (!/^[a-z0-9_]{3,20}$/.test(id || "")) return E(req, "아이디는 영문 소문자·숫자·밑줄 3~20자예요");
        if (typeof pw !== "string" || pw.length < 6 || pw.length > 72) return E(req, "비밀번호는 6자 이상이에요");
        const ip = req.headers.get("CF-Connecting-IP") || "";
        const iph = await sha256(ip + env.PEPPER);
        const cnt = await db.prepare("SELECT COUNT(*) n FROM signup_rl WHERE ip_hash = ? AND at > ?").bind(iph, new Date(Date.now() - 3600e3).toISOString()).first();
        if (cnt.n >= LIMITS.signupPerHour) return E(req, "잠시 후 다시 시도해 주세요", 429);
        if (await db.prepare("SELECT 1 FROM users WHERE id = ?").bind(id).first()) return E(req, "이미 있는 아이디예요");
        const salt = rand(16);
        await db.batch([
          db.prepare("INSERT INTO users (id, pw_hash, salt, points, created) VALUES (?,?,?,0,?)").bind(id, await pwHash(pw, salt, env.PEPPER), salt, now()),
          db.prepare("INSERT INTO signup_rl (ip_hash, at) VALUES (?,?)").bind(iph, now()),
        ]);
        await addPoints(db, id, POINTS.signup, "signup");
        const bonus = await loginBonus(db, id);
        return J(req, { ok: true, token: await newSession(db, id, "web"), bonus: POINTS.signup + bonus, me: await me(db, id) });
      }
      if (p === "/api/login" && req.method === "POST") {
        const { id, pw, kind } = await req.json();
        const u = await db.prepare("SELECT id, pw_hash, salt, banned FROM users WHERE id = ?").bind(String(id || "")).first();
        if (!u || u.banned || (await pwHash(String(pw || ""), u.salt, env.PEPPER)) !== u.pw_hash) return E(req, "아이디 또는 비밀번호가 맞지 않아요", 401);
        const bonus = await loginBonus(db, u.id);
        return J(req, { ok: true, token: await newSession(db, u.id, kind === "agent" ? "agent" : "web"), bonus, me: await me(db, u.id) });
      }
      if (p === "/api/logout" && req.method === "POST") {
        const h = req.headers.get("Authorization") || "";
        if (h.startsWith("Bearer ")) await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(h.slice(7))).run();
        return J(req, { ok: true });
      }
      if (p === "/api/me") {
        const a = await auth(req, db); if (!a) return E(req, "로그인이 필요해요", 401);
        const bonus = await loginBonus(db, a.user_id);
        return J(req, { ok: true, bonus, me: await me(db, a.user_id) });
      }

      // ── 오래된 게재면 고화질 원본 요청(포인트 차감) ──
      if (p === "/api/od" && req.method === "POST") {
        const a = await auth(req, db); if (!a) return E(req, "로그인이 필요해요", 401);
        const { ad } = await req.json();
        const adId = parseInt(ad, 10); if (!adId) return E(req, "잘못된 요청이에요");
        const r = await db.prepare("UPDATE users SET points = points - ? WHERE id = ? AND points >= ?").bind(POINTS.od_cost, a.user_id, POINTS.od_cost).run();
        if (!r.meta.changes) return E(req, `포인트가 부족해요(원본 불러오기 ${POINTS.od_cost}P)`, 402);
        await db.batch([
          db.prepare("INSERT INTO ledger (user_id, delta, reason, ref, at) VALUES (?,?,?,?,?)").bind(a.user_id, -POINTS.od_cost, "od", String(adId), now()),
          db.prepare("INSERT INTO od_requests (user_id, ad_id, status, created) VALUES (?,?, 'pending', ?)").bind(a.user_id, adId, now()),
        ]);
        return J(req, { ok: true, cost: POINTS.od_cost, me: await me(db, a.user_id) });
      }

      // ── 참여자 수집기 ─────────────────────────
      if (p === "/api/agent/hello" && req.method === "POST") {
        const a = await auth(req, db); if (!a || a.kind !== "agent") return E(req, "수집기 로그인이 필요해요", 401);
        return J(req, { ok: true, points: POINTS, limits: LIMITS, me: await me(db, a.user_id) });
      }
      if (p === "/api/agent/upload" && req.method === "POST") {
        const a = await auth(req, db); if (!a || a.kind !== "agent") return E(req, "수집기 로그인이 필요해요", 401);
        if (+(req.headers.get("Content-Length") || 0) > LIMITS.bodyMax) return E(req, "파일이 너무 커요", 413);
        const day = kstDay();
        const cnt = await db.prepare("SELECT COUNT(*) n FROM inbox_log WHERE user_id = ? AND day = ?").bind(a.user_id, day).first();
        if (cnt.n >= LIMITS.uploadsPerDay) return E(req, "오늘 접수 한도에 도달했어요(내일 다시)", 429);
        const form = await req.formData();
        let meta;
        try { meta = JSON.parse(form.get("meta") || "{}"); } catch { return E(req, "잘못된 데이터예요"); }
        const key = String(meta.key || "");
        if (!/^[a-z_]+:[\w:.-]{6,80}$/.test(key) || !PLACEMENTS.includes(meta.placement)) return E(req, "잘못된 데이터예요");
        if (await db.prepare("SELECT 1 FROM inbox_log WHERE ad_key = ?").bind(key).first()) return J(req, { ok: true, duplicate: true, points: 0 });
        const files = [];
        for (const [name, v] of form.entries()) {
          if (name === "meta" || typeof v === "string") continue;
          if (!/^(0[1-8]|landing)\.jpg$/.test(name)) return E(req, "허용되지 않는 파일이에요");
          const buf = await v.arrayBuffer();
          const b = new Uint8Array(buf);
          if (buf.byteLength > LIMITS.fileMax || b[0] !== 0xff || b[1] !== 0xd8) return E(req, "이미지가 올바르지 않아요");
          files.push([name, buf]);
        }
        if (!files.length || files.length > LIMITS.filesMax) return E(req, "이미지 개수가 올바르지 않아요");
        const ins = await db.prepare("INSERT INTO inbox_log (user_id, ad_key, placement, meta, status, day, created, points) VALUES (?,?,?,?, 'pending', ?, ?, ?)")
          .bind(a.user_id, key, meta.placement, JSON.stringify(meta).slice(0, 20000), day, now(), 0).run();
        const iid = ins.meta.last_row_id;
        await db.batch(files.map(([n, buf]) => db.prepare("INSERT INTO inbox_files (inbox_id, name, data) VALUES (?,?,?)").bind(iid, n, buf)));
        // 포인트는 중앙 PC가 '새 광고'로 확인한 뒤 지급(후불)
        return J(req, { ok: true, queued: true, points: 0, pending_reward: POINTS.new_ad });
      }
      if (p === "/api/agent/sighting" && req.method === "POST") {
        const a = await auth(req, db); if (!a || a.kind !== "agent") return E(req, "수집기 로그인이 필요해요", 401);
        const { key, placement, context } = await req.json();
        if (!/^[a-z_]+:[\w:.-]{6,80}$/.test(String(key || "")) || !PLACEMENTS.includes(placement)) return E(req, "잘못된 데이터예요");
        await db.prepare("INSERT INTO sightings (user_id, ad_key, placement, context, at) VALUES (?,?,?,?,?)")
          .bind(a.user_id, key, placement, String(context || "").slice(0, 300), now()).run();
        return J(req, { ok: true });
      }

      // ── 중앙 PC 전용 ──────────────────────────
      if (p.startsWith("/api/admin/")) {
        const h = req.headers.get("Authorization") || "";
        if (!sec.ADMIN_HASH || !h.startsWith("Bearer ") || (await sha256(h.slice(7))) !== sec.ADMIN_HASH) return E(req, "권한 없음", 403);
        if (p === "/api/admin/inbox") {
          const r = await db.prepare("SELECT id, user_id, ad_key, placement, meta, created FROM inbox_log WHERE status = 'pending' ORDER BY id LIMIT 10").all();
          for (const x of r.results) x.files = (await db.prepare("SELECT id, name, length(data) size FROM inbox_files WHERE inbox_id = ?").bind(x.id).all()).results;
          return J(req, { ok: true, items: r.results });
        }
        let m = p.match(/^\/api\/admin\/file\/(\d+)$/);
        if (m) {
          const f = await db.prepare("SELECT data FROM inbox_files WHERE id = ?").bind(+m[1]).first();
          return f ? new Response(new Uint8Array(f.data), { headers: { "Content-Type": "image/jpeg" } }) : E(req, "없음", 404);
        }
        m = p.match(/^\/api\/admin\/inbox\/(\d+)\/result$/);
        if (m && req.method === "POST") {
          const { status, note, ad_id } = await req.json();   // accepted | duplicate | rejected
          const row = await db.prepare("SELECT user_id, points, status FROM inbox_log WHERE id = ?").bind(+m[1]).first();
          if (!row) return E(req, "없음", 404);
          await db.batch([
            db.prepare("UPDATE inbox_log SET status = ?, note = ?, central_ad_id = ? WHERE id = ?").bind(status, String(note || ""), ad_id || null, +m[1]),
            db.prepare("DELETE FROM inbox_files WHERE inbox_id = ?").bind(+m[1]),
          ]);
          if (row.status === "pending" && status === "accepted") {
            await db.prepare("UPDATE inbox_log SET points = ? WHERE id = ?").bind(POINTS.new_ad, +m[1]).run();
            await addPoints(db, row.user_id, POINTS.new_ad, "new_ad", ad_id || m[1]);
          }
          return J(req, { ok: true });
        }
        if (p === "/api/admin/od") {
          const r = await db.prepare("SELECT id, ad_id FROM od_requests WHERE status = 'pending' ORDER BY id LIMIT 10").all();
          return J(req, { ok: true, items: r.results });
        }
        m = p.match(/^\/api\/admin\/od\/(\d+)\/(done|refund)$/);
        if (m && req.method === "POST") {
          const row = await db.prepare("SELECT user_id, status FROM od_requests WHERE id = ?").bind(+m[1]).first();
          if (!row) return E(req, "없음", 404);
          await db.prepare("UPDATE od_requests SET status = ? WHERE id = ?").bind(m[2], +m[1]).run();
          if (m[2] === "refund" && row.status === "pending") await addPoints(db, row.user_id, POINTS.od_cost, "od_refund", m[1]);
          return J(req, { ok: true });
        }
        if (p === "/api/admin/sightings") {
          const r = await db.prepare("SELECT id, user_id, ad_key, placement, context, at FROM sightings ORDER BY id LIMIT 500").all();
          if (r.results.length) await db.prepare("DELETE FROM sightings WHERE id <= ?").bind(r.results[r.results.length - 1].id).run();
          return J(req, { ok: true, items: r.results });
        }
        if (p === "/api/admin/stats") {
          const u = await db.prepare("SELECT COUNT(*) n FROM users").first();
          const pend = await db.prepare("SELECT COUNT(*) n FROM inbox_log WHERE status = 'pending'").first();
          return J(req, { ok: true, users: u.n, pending: pend.n });
        }
      }
      if (p === "/api/ping") return J(req, { ok: true, at: now() });
      return E(req, "없는 주소예요", 404);
    } catch (e) {
      return E(req, "서버 오류: " + (e && e.message ? e.message.slice(0, 120) : "unknown"), 500);
    }
  },
};
