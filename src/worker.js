// Focus Global backend: one Durable Object (SQLite) holds students and classes.
// Static pages in /public are served by Cloudflare; only /api/* reaches this code.
import { DurableObject } from "cloudflare:workers";

// Hash of the first admin password (salt$hash, PBKDF2-SHA256, 100k rounds).
// Change the password from the admin page; the new hash is stored in the database.
const DEFAULT_ADMIN_HASH = "iyvK5HWMUD9cVkaxMCMBaA$InBwZQf4E8itFjlFQtffd5AjVzfs5Zknjom_LuPs2yQ";

const ITER = 100000;
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(t + "=".repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
};
const same = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
};
async function pbkdf2(pw, saltB64) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64u(saltB64), iterations: ITER }, key, 256);
  return b64u(bits);
}
async function makeHash(pw) {
  const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
  return salt + "$" + (await pbkdf2(pw, salt));
}
async function checkHash(pw, stored) {
  if (!stored || !pw) return false;
  const [salt, h] = stored.split("$");
  return same(await pbkdf2(pw, salt), h);
}

const WORDS = ["mango", "river", "tiger", "lotus", "cloud", "maple", "comet", "pearl", "cedar", "eagle", "ocean", "piano",
  "amber", "delta", "ember", "frost", "grove", "honey", "ivory", "jolly", "koala", "lemon", "mint", "noble", "olive",
  "panda", "quilt", "robin", "sunny", "tulip", "unity", "vivid", "willow", "zebra", "kiwi", "coral", "spark", "orbit"];
function newPassword() {
  const r = crypto.getRandomValues(new Uint32Array(3));
  return `${WORDS[r[0] % WORDS.length]}-${String(1000 + (r[1] % 9000))}-${WORDS[r[2] % WORDS.length]}`;
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const fail = (msg, status = 400) => json({ error: msg }, status);
const str = (v, max = 2000) => (v == null ? "" : String(v).trim().slice(0, max));

const STUDENT_FIELDS = ["name", "country", "city", "tz", "grade", "subjects", "guardian", "phone", "email", "meet_link", "teacher", "notes"];
const PUBLIC_STUDENT = "id, name, country, city, tz, grade, subjects, guardian, meet_link, teacher";

export class Store extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => this.setup());
  }

  q(query, ...args) {
    return this.sql.exec(query, ...args).toArray();
  }
  one(query, ...args) {
    return this.q(query, ...args)[0] || null;
  }

  async setup() {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS students (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, pw TEXT, country TEXT, city TEXT, tz TEXT, grade TEXT, subjects TEXT,
      guardian TEXT, phone TEXT, email TEXT, meet_link TEXT, teacher TEXT, notes TEXT, created TEXT)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT, student_id TEXT NOT NULL, start_utc TEXT NOT NULL, mins INTEGER DEFAULT 60,
      subject TEXT, teacher TEXT, status TEXT DEFAULT 'scheduled', topic TEXT, homework TEXT, hw_done INTEGER DEFAULT 0,
      note TEXT, created TEXT)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS attempts (k TEXT PRIMARY KEY, n INTEGER, first INTEGER)`);
    const get = (k) => this.one(`SELECT v FROM meta WHERE k=?`, k)?.v;
    if (!get("secret")) this.sql.exec(`INSERT INTO meta VALUES ('secret', ?)`, b64u(crypto.getRandomValues(new Uint8Array(32))));
    if (!get("admin_pw")) this.sql.exec(`INSERT INTO meta VALUES ('admin_pw', ?)`, DEFAULT_ADMIN_HASH);
    if (!get("seeded")) {
      this.sql.exec(
        `INSERT OR IGNORE INTO students (id, name, country, city, tz, created) VALUES ('2026NZ001', 'Yashna', 'NZ', '', 'Pacific/Auckland', ?)`,
        new Date().toISOString()
      );
      this.sql.exec(`INSERT INTO meta VALUES ('seeded', '1')`);
    }
    this.secret = await crypto.subtle.importKey("raw", fromB64u(get("secret")), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  }

  // ---- tokens ----
  async sign(payload) {
    const body = b64u(enc.encode(JSON.stringify(payload)));
    const sig = b64u(await crypto.subtle.sign("HMAC", this.secret, enc.encode(body)));
    return body + "." + sig;
  }
  async verify(req) {
    const h = req.headers.get("authorization") || "";
    const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
    const [body, sig] = tok.split(".");
    if (!body || !sig) return null;
    let ok = false;
    try { ok = await crypto.subtle.verify("HMAC", this.secret, fromB64u(sig), enc.encode(body)); } catch { return null; }
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(fromB64u(body)));
    if (!p.exp || p.exp < Date.now()) return null;
    if (p.r === "a" && p.v !== (this.one(`SELECT v FROM meta WHERE k='admin_ver'`)?.v || "0")) return null;
    if (p.r === "s") {
      const s = this.one(`SELECT pw FROM students WHERE id=?`, p.id);
      if (!s || !s.pw || s.pw.slice(0, 8) !== p.v) return null; // password reset logs students out
    }
    return p;
  }

  // ---- brute-force protection: 8 failures per 15 minutes per key ----
  limited(key) {
    const row = this.one(`SELECT n, first FROM attempts WHERE k=?`, key);
    return row && Date.now() - row.first < 15 * 60e3 && row.n >= 8;
  }
  failed(key) {
    const row = this.one(`SELECT n, first FROM attempts WHERE k=?`, key);
    if (!row || Date.now() - row.first > 15 * 60e3) this.sql.exec(`INSERT OR REPLACE INTO attempts VALUES (?, 1, ?)`, key, Date.now());
    else this.sql.exec(`UPDATE attempts SET n=n+1 WHERE k=?`, key);
  }

  async fetch(req) {
    try {
      return await this.route(req);
    } catch (e) {
      return fail("Something went wrong on our side. Please try again.", 500);
    }
  }

  async route(req) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "");
    const m = req.method;
    const body = m === "GET" || m === "DELETE" ? {} : await req.json().catch(() => ({}));
    const ip = req.headers.get("cf-connecting-ip") || "local";

    // ---------- student ----------
    if (path === "/api/login" && m === "POST") {
      const id = str(body.id, 40).toUpperCase();
      if (this.limited("s:" + id) || this.limited("ip:" + ip)) return fail("Too many attempts. Please wait 15 minutes and try again.", 429);
      const s = this.one(`SELECT id, name, pw FROM students WHERE id=?`, id);
      if (!s || !(await checkHash(str(body.password, 200), s.pw))) {
        this.failed("s:" + id); this.failed("ip:" + ip);
        return fail("That Student ID or password is incorrect.", 401);
      }
      const token = await this.sign({ r: "s", id: s.id, v: s.pw.slice(0, 8), exp: Date.now() + 30 * 864e5 });
      return json({ token, name: s.name });
    }

    if (path.startsWith("/api/me")) {
      const p = await this.verify(req);
      if (!p || p.r !== "s") return fail("Please log in again.", 401);
      if (path === "/api/me" && m === "GET") {
        const student = this.one(`SELECT ${PUBLIC_STUDENT} FROM students WHERE id=?`, p.id);
        const classes = this.q(
          `SELECT id, start_utc, mins, subject, teacher, status, topic, homework, hw_done, note FROM classes WHERE student_id=? ORDER BY start_utc`,
          p.id
        );
        return json({ student, classes, now: new Date().toISOString() });
      }
      if (path === "/api/me/homework" && m === "POST") {
        this.sql.exec(`UPDATE classes SET hw_done=? WHERE id=? AND student_id=?`, body.done ? 1 : 0, Number(body.classId) || 0, p.id);
        return json({ ok: true });
      }
      return fail("Not found", 404);
    }

    // ---------- admin ----------
    if (path === "/api/admin/login" && m === "POST") {
      if (this.limited("admin") || this.limited("ip:" + ip)) return fail("Too many attempts. Please wait 15 minutes and try again.", 429);
      const stored = this.one(`SELECT v FROM meta WHERE k='admin_pw'`)?.v;
      if (!(await checkHash(str(body.password, 200), stored))) {
        this.failed("admin"); this.failed("ip:" + ip);
        return fail("That password is incorrect.", 401);
      }
      const v = this.one(`SELECT v FROM meta WHERE k='admin_ver'`)?.v || "0";
      return json({ token: await this.sign({ r: "a", v, exp: Date.now() + 14 * 864e5 }) });
    }

    if (!path.startsWith("/api/admin/")) return fail("Not found", 404);
    const p = await this.verify(req);
    if (!p || p.r !== "a") return fail("Please log in again.", 401);
    const seg = path.split("/").slice(3); // after /api/admin

    if (seg[0] === "password" && m === "POST") {
      const stored = this.one(`SELECT v FROM meta WHERE k='admin_pw'`)?.v;
      if (!(await checkHash(str(body.current, 200), stored))) return fail("Your current password is incorrect.", 400);
      const next = str(body.next, 200);
      if (next.length < 10) return fail("Use at least 10 characters for the new password.");
      this.sql.exec(`INSERT OR REPLACE INTO meta VALUES ('admin_pw', ?)`, await makeHash(next));
      const v = String(Date.now());
      this.sql.exec(`INSERT OR REPLACE INTO meta VALUES ('admin_ver', ?)`, v);
      return json({ token: await this.sign({ r: "a", v, exp: Date.now() + 14 * 864e5 }) });
    }

    if (seg[0] === "students") {
      const id = seg[1] ? decodeURIComponent(seg[1]).toUpperCase() : null;
      if (!id && m === "GET") {
        const rows = this.q(`SELECT id, name, country, city, tz, grade, subjects, guardian, phone, email, meet_link, teacher, notes, created,
          (pw IS NOT NULL) AS has_pw FROM students ORDER BY id`);
        const now = new Date().toISOString();
        for (const r of rows) {
          r.next = this.one(`SELECT start_utc, subject FROM classes WHERE student_id=? AND start_utc>=? AND status!='cancelled' ORDER BY start_utc LIMIT 1`, r.id, now);
          r.count = this.one(`SELECT COUNT(*) AS c FROM classes WHERE student_id=?`, r.id).c;
        }
        return json({ students: rows });
      }
      if (!id && m === "POST") {
        const name = str(body.name, 80);
        if (!name) return fail("Add the student's name.");
        const cc = (str(body.country, 2).toUpperCase().replace(/[^A-Z]/g, "") || "XX").padEnd(2, "X");
        const prefix = new Date().getUTCFullYear() + cc;
        const last = this.one(`SELECT id FROM students WHERE id LIKE ? ORDER BY id DESC LIMIT 1`, prefix + "%");
        const sid = prefix + String((last ? parseInt(last.id.slice(prefix.length), 10) || 0 : 0) + 1).padStart(3, "0");
        const pw = newPassword();
        const vals = STUDENT_FIELDS.map((f) => (f === "country" ? cc : str(body[f])));
        this.sql.exec(
          `INSERT INTO students (id, pw, ${STUDENT_FIELDS.join(", ")}, created) VALUES (?, ?, ${STUDENT_FIELDS.map(() => "?").join(", ")}, ?)`,
          sid, await makeHash(pw), ...vals, new Date().toISOString()
        );
        return json({ id: sid, password: pw });
      }
      if (id && !this.one(`SELECT id FROM students WHERE id=?`, id)) return fail("Student not found.", 404);
      if (id && seg[2] === "password" && m === "POST") {
        const pw = newPassword();
        this.sql.exec(`UPDATE students SET pw=? WHERE id=?`, await makeHash(pw), id);
        return json({ id, password: pw });
      }
      if (id && !seg[2] && m === "PATCH") {
        const sets = STUDENT_FIELDS.filter((f) => f in body);
        if (!sets.length) return json({ ok: true });
        if (sets.includes("name") && !str(body.name)) return fail("Name cannot be empty.");
        this.sql.exec(`UPDATE students SET ${sets.map((f) => f + "=?").join(", ")} WHERE id=?`,
          ...sets.map((f) => (f === "country" ? str(body[f], 2).toUpperCase() : str(body[f]))), id);
        return json({ ok: true });
      }
      if (id && !seg[2] && m === "DELETE") {
        this.sql.exec(`DELETE FROM classes WHERE student_id=?`, id);
        this.sql.exec(`DELETE FROM students WHERE id=?`, id);
        return json({ ok: true });
      }
    }

    if (seg[0] === "classes") {
      const cid = seg[1] ? Number(seg[1]) : null;
      if (!cid && m === "GET") {
        const sid = str(url.searchParams.get("student"), 40).toUpperCase();
        return json({ classes: this.q(`SELECT * FROM classes WHERE student_id=? ORDER BY start_utc`, sid) });
      }
      if (!cid && m === "POST") {
        const sid = str(body.student_id, 40).toUpperCase();
        if (!this.one(`SELECT id FROM students WHERE id=?`, sid)) return fail("Student not found.", 404);
        const start = new Date(str(body.start_utc, 40));
        if (isNaN(start)) return fail("Pick a valid date and time.");
        const n = Math.min(Math.max(Number(body.repeat) || 1, 1), 26);
        for (let i = 0; i < n; i++) {
          this.sql.exec(
            `INSERT INTO classes (student_id, start_utc, mins, subject, teacher, status, topic, homework, note, created) VALUES (?, ?, ?, ?, ?, 'scheduled', '', '', '', ?)`,
            sid, new Date(start.getTime() + i * 7 * 864e5).toISOString(), Math.min(Math.max(Number(body.mins) || 60, 15), 240),
            str(body.subject, 80), str(body.teacher, 80), new Date().toISOString()
          );
        }
        return json({ ok: true, added: n });
      }
      if (cid && m === "PATCH") {
        const allowed = ["start_utc", "mins", "subject", "teacher", "status", "topic", "homework", "note", "hw_done"];
        const sets = allowed.filter((f) => f in body);
        if (body.status && !["scheduled", "present", "absent", "cancelled"].includes(body.status)) return fail("Unknown status.");
        if (body.start_utc && isNaN(new Date(body.start_utc))) return fail("Pick a valid date and time.");
        const vals = sets.map((f) =>
          f === "mins" ? Math.min(Math.max(Number(body.mins) || 60, 15), 240)
          : f === "hw_done" ? (body.hw_done ? 1 : 0)
          : f === "start_utc" ? new Date(body.start_utc).toISOString()
          : str(body[f]));
        if (sets.length) this.sql.exec(`UPDATE classes SET ${sets.map((f) => f + "=?").join(", ")} WHERE id=?`, ...vals, cid);
        return json({ ok: true });
      }
      if (cid && m === "DELETE") {
        this.sql.exec(`DELETE FROM classes WHERE id=?`, cid);
        return json({ ok: true });
      }
    }
    return fail("Not found", 404);
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/api/")) {
      return env.STORE.get(env.STORE.idFromName("main")).fetch(req);
    }
    return env.ASSETS.fetch(req);
  },
};
