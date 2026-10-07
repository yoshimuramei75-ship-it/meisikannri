import express from "express";
import multer from "multer";
import pg from "pg";
import crypto from "node:crypto";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const FIELDS = ["company", "department", "title", "name", "name_kana", "phone", "mobile", "fax", "email", "address", "url", "met_place", "memo"];
const OCR_FIELDS = FIELDS.filter((f) => f !== "memo" && f !== "met_place");
// 合言葉。Render の環境変数 INVITE_CODE を設定すると、新規登録に合言葉が必要になる（空なら誰でも登録可）
const INVITE_CODE = (process.env.INVITE_CODE || "").trim();
const COOKIE = "meishi_session";
const REMEMBER_DAYS = 30;
const scrypt = promisify(crypto.scrypt);

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL が設定されていません");
  process.exit(1);
}

// Render の内部接続は SSL 不要。外部接続URLを使う場合は PGSSL=true を設定。
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

let SECRET = null; // ログイン情報の署名鍵（起動時にDBから読み込む）

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cards (
      id          UUID PRIMARY KEY,
      company     TEXT NOT NULL DEFAULT '',
      department  TEXT NOT NULL DEFAULT '',
      title       TEXT NOT NULL DEFAULT '',
      name        TEXT NOT NULL DEFAULT '',
      name_kana   TEXT NOT NULL DEFAULT '',
      phone       TEXT NOT NULL DEFAULT '',
      mobile      TEXT NOT NULL DEFAULT '',
      fax         TEXT NOT NULL DEFAULT '',
      email       TEXT NOT NULL DEFAULT '',
      address     TEXT NOT NULL DEFAULT '',
      url         TEXT NOT NULL DEFAULT '',
      memo        TEXT NOT NULL DEFAULT '',
      image       BYTEA,
      image_type  TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
  // v2: 会った場所・タグ
  await pool.query(`ALTER TABLE cards ADD COLUMN IF NOT EXISTS met_place TEXT NOT NULL DEFAULT ''`);
  await pool.query(`ALTER TABLE cards ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}'`);
  // v4: メンバー・登録者・自分だけのメモ
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id              UUID PRIMARY KEY,
      login_id        TEXT NOT NULL UNIQUE,
      display_name    TEXT NOT NULL,
      password_hash   TEXT NOT NULL,
      is_admin        BOOLEAN NOT NULL DEFAULT false,
      disabled        BOOLEAN NOT NULL DEFAULT false,
      session_version INTEGER NOT NULL DEFAULT 1,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
  await pool.query(`ALTER TABLE cards ADD COLUMN IF NOT EXISTS created_by UUID`);
  await pool.query(`ALTER TABLE cards ADD COLUMN IF NOT EXISTS created_by_name TEXT NOT NULL DEFAULT ''`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS private_notes (
      user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      card_id    UUID NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
      note       TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, card_id)
    )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  // v5: IDをやめて名前でログイン。以前IDで登録した人も名前でログインできるようにそろえる
  try {
    await pool.query(`UPDATE users SET login_id = lower(regexp_replace(normalize(display_name, NFKC), '\\s', '', 'g'))`);
  } catch (e) { console.error("名前ログインへの移行で重複がありました。管理者が名前を変えてください:", e.detail || e.message); }

  // 署名鍵：環境変数 SESSION_SECRET があればそれを、無ければ初回起動時に作ってDBに保存
  if (process.env.SESSION_SECRET) {
    SECRET = crypto.createHash("sha256").update(process.env.SESSION_SECRET).digest();
  } else {
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ('session_secret', $1) ON CONFLICT (key) DO NOTHING`,
      [crypto.randomBytes(32).toString("hex")]
    );
    const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'session_secret'`);
    SECRET = Buffer.from(rows[0].value, "hex");
  }
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // Render のプロキシ経由でも https と接続元IPを正しく判定する

app.get("/healthz", (_req, res) => res.send("ok"));

// ======================= ログイン・メンバー =======================
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}
async function checkPassword(pw, stored) {
  const [, saltHex, keyHex] = String(stored || "scrypt$00$00").split("$");
  const key = await scrypt(String(pw), Buffer.from(saltHex, "hex"), 64);
  const expect = Buffer.from(keyHex, "hex");
  return expect.length === key.length && crypto.timingSafeEqual(key, expect);
}
const DUMMY_HASH = "scrypt$" + "00".repeat(16) + "$" + "00".repeat(64);

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return `${body}.${mac}`;
}
function readToken(token) {
  if (!token) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expect = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  if (!safeEqual(mac, expect)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp && p.exp > Date.now() && p.uid ? p : null;
  } catch { return null; }
}
function readCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function setSession(req, res, user, remember) {
  const ms = remember ? REMEMBER_DAYS * 86400e3 : 12 * 3600e3;
  const token = sign({ uid: user.id, v: user.session_version, r: remember ? 1 : 0, exp: Date.now() + ms });
  const parts = [`${COOKIE}=${token}`, "Path=/", "HttpOnly", "SameSite=Lax"];
  if (req.secure) parts.push("Secure");
  if (remember) parts.push(`Max-Age=${REMEMBER_DAYS * 86400}`); // 記憶しない場合はブラウザを閉じると消える
  res.append("Set-Cookie", parts.join("; "));
}
function clearSession(req, res) {
  res.append("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${req.secure ? "; Secure" : ""}`);
}
async function currentUser(req) {
  const p = readToken(readCookie(req, COOKIE));
  if (!p) return null;
  const { rows } = await pool.query(
    `SELECT id, login_id, display_name, is_admin, disabled, session_version FROM users WHERE id = $1`, [p.uid]);
  const u = rows[0];
  if (!u || u.disabled || u.session_version !== p.v) return null;
  u.token = p;
  return u;
}
const publicUser = (u) => ({ id: u.id, login_id: u.login_id, name: u.display_name, is_admin: u.is_admin });

// 総当たり対策：同じ接続元から15分で10回失敗したら一時的に止める
const failures = new Map();
function isLocked(ip) { const f = failures.get(ip); return !!(f && f.n >= 10 && f.until > Date.now()); }
function recordFail(ip) {
  const now = Date.now(), f = failures.get(ip);
  if (!f || f.until < now) failures.set(ip, { n: 1, until: now + 15 * 60e3 });
  else f.n++;
}

// ログイン済みならログイン画面ではなく一覧へ
app.get(["/login", "/login.html"], async (req, res, next) => {
  try {
    if (await currentUser(req)) return res.redirect(302, "/");
    if (req.path === "/login") return res.redirect(302, "/login.html");
    next();
  } catch (e) { next(e); }
});

const OPEN_PATHS = new Set(["/login.html", "/api/login", "/api/register", "/api/auth-config", "/api/logout", "/healthz"]);
app.use(async (req, res, next) => {
  if (OPEN_PATHS.has(req.path)) return next();
  try {
    const u = await currentUser(req);
    if (u) {
      req.user = u;
      // 「ログインしたままにする」の場合、使っている間は期限を自動で延長する
      if (u.token.r && u.token.exp - Date.now() < (REMEMBER_DAYS / 2) * 86400e3) setSession(req, res, u, true);
      return next();
    }
    if (req.path.startsWith("/api/")) return res.status(401).json({ error: "ログインが必要です", login: true });
    res.redirect(302, "/login.html");
  } catch (e) { next(e); }
});

app.use(express.json({ limit: "200kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/auth-config", async (_req, res, next) => {
  try {
    const { rows } = await pool.query(`SELECT EXISTS (SELECT 1 FROM users) AS has`);
    res.json({ inviteRequired: !!INVITE_CODE, hasUsers: rows[0].has });
  } catch (e) { next(e); }
});

// 名前でログインする。全角・半角やスペースの有無の違いは同じ名前として扱う
function cleanName(s) { return String(s || "").normalize("NFKC").trim().replace(/\s+/g, " ").slice(0, 40); }
function nameKey(s) { return cleanName(s).replace(/\s/g, "").toLowerCase(); }
const NAME_TAKEN = "その名前はすでに登録されています。同じ名字の人がいる場合は、フルネームで登録してください。";
function checkNewPassword(pw) {
  if (typeof pw !== "string" || pw.length < 8) return "パスワードは8文字以上にしてください。";
  if (pw.length > 200) return "パスワードが長すぎます。";
  return null;
}

app.post("/api/register", async (req, res, next) => {
  try {
    if (isLocked(req.ip)) return res.status(429).json({ error: "しばらく待ってからお試しください。" });
    const { name = "", password = "", invite = "", remember = true } = req.body || {};
    if (INVITE_CODE && !safeEqual(String(invite).trim(), INVITE_CODE)) {
      recordFail(req.ip);
      return res.status(403).json({ error: "合言葉が違います。" });
    }
    const displayName = cleanName(name);
    const loginId = nameKey(name);
    if (!loginId) return res.status(400).json({ error: "名前を入力してください。" });
    const pwErr = checkNewPassword(password);
    if (pwErr) return res.status(400).json({ error: pwErr });

    const hash = await hashPassword(password);
    const client = await pool.connect();
    let user;
    try {
      await client.query("BEGIN");
      await client.query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE"); // 最初の1人を確実に管理者にする
      const { rows: cnt } = await client.query("SELECT COUNT(*)::int AS n FROM users");
      const { rows } = await client.query(
        `INSERT INTO users (id, login_id, display_name, password_hash, is_admin) VALUES ($1, $2, $3, $4, $5)
         RETURNING id, login_id, display_name, is_admin, session_version`,
        [crypto.randomUUID(), loginId, displayName, hash, cnt[0].n === 0]
      );
      await client.query("COMMIT");
      user = rows[0];
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      if (e.code === "23505") return res.status(409).json({ error: NAME_TAKEN });
      throw e;
    } finally { client.release(); }
    setSession(req, res, user, !!remember);
    res.status(201).json(publicUser(user));
  } catch (e) { next(e); }
});

app.post("/api/login", async (req, res, next) => {
  try {
    if (isLocked(req.ip)) return res.status(429).json({ error: "ログインの失敗が続いたため、15分ほど待ってからお試しください。" });
    const { name = "", password = "", remember = false } = req.body || {};
    const { rows } = await pool.query(
      `SELECT id, login_id, display_name, password_hash, is_admin, disabled, session_version FROM users WHERE login_id = $1`,
      [nameKey(name)]
    );
    const u = rows[0];
    const ok = await checkPassword(password, u ? u.password_hash : DUMMY_HASH);
    if (!u || !ok) {
      recordFail(req.ip);
      await new Promise((r) => setTimeout(r, 400));
      return res.status(401).json({ error: "名前またはパスワードが違います。" });
    }
    if (u.disabled) return res.status(403).json({ error: "このアカウントは利用停止されています。管理者に確認してください。" });
    failures.delete(req.ip);
    setSession(req, res, u, !!remember);
    res.json(publicUser(u));
  } catch (e) { next(e); }
});

app.post("/api/logout", (req, res) => { clearSession(req, res); res.json({ ok: true }); });

app.get("/api/me", (req, res) => res.json(publicUser(req.user)));

app.put("/api/me", async (req, res, next) => {
  try {
    const displayName = cleanName(req.body?.name);
    if (!displayName) return res.status(400).json({ error: "名前を入力してください。" });
    try {
      const { rows } = await pool.query(
        `UPDATE users SET display_name = $2, login_id = $3 WHERE id = $1 RETURNING id, login_id, display_name, is_admin`,
        [req.user.id, displayName, nameKey(displayName)]);
      res.json(publicUser(rows[0]));
    } catch (e) {
      if (e.code === "23505") return res.status(409).json({ error: NAME_TAKEN });
      throw e;
    }
  } catch (e) { next(e); }
});

app.put("/api/me/password", async (req, res, next) => {
  try {
    const { current = "", next: newPw = "" } = req.body || {};
    const { rows } = await pool.query(`SELECT password_hash FROM users WHERE id = $1`, [req.user.id]);
    if (!(await checkPassword(current, rows[0]?.password_hash))) return res.status(400).json({ error: "今のパスワードが違います。" });
    const pwErr = checkNewPassword(newPw);
    if (pwErr) return res.status(400).json({ error: pwErr });
    // ほかの端末のログインは解除し、この端末だけログインし直す
    const { rows: u } = await pool.query(
      `UPDATE users SET password_hash = $2, session_version = session_version + 1 WHERE id = $1
       RETURNING id, login_id, display_name, is_admin, session_version`,
      [req.user.id, await hashPassword(newPw)]
    );
    setSession(req, res, u[0], !!req.user.token.r);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ---- 管理者用：メンバー管理 ----
function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: "管理者だけが使える機能です。" });
  next();
}
app.get("/api/users", adminOnly, async (_req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.login_id, u.display_name AS name, u.is_admin, u.disabled, u.created_at,
              (SELECT COUNT(*)::int FROM cards c WHERE c.created_by = u.id) AS card_count
       FROM users u ORDER BY u.created_at`);
    res.json(rows);
  } catch (e) { next(e); }
});
app.put("/api/users/:id", adminOnly, async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: "自分自身の権限や利用停止は変更できません。" });
    const sets = [], vals = [req.params.id];
    if (typeof req.body?.disabled === "boolean") { vals.push(req.body.disabled); sets.push(`disabled = $${vals.length}`); }
    if (typeof req.body?.is_admin === "boolean") { vals.push(req.body.is_admin); sets.push(`is_admin = $${vals.length}`); }
    if (!sets.length) return res.status(400).json({ error: "変更内容がありません。" });
    // 利用停止にしたら、その人の端末のログインもすぐ解除する
    const { rows } = await pool.query(
      `UPDATE users SET ${sets.join(", ")}, session_version = session_version + 1 WHERE id = $1
       RETURNING id, login_id, display_name AS name, is_admin, disabled, created_at`, vals);
    if (!rows[0]) return res.status(404).json({ error: "見つかりません" });
    res.json(rows[0]);
  } catch (e) { next(e); }
});
app.post("/api/users/:id/password", adminOnly, async (req, res, next) => {
  try {
    const pwErr = checkNewPassword(req.body?.password);
    if (pwErr) return res.status(400).json({ error: pwErr });
    const { rowCount } = await pool.query(
      `UPDATE users SET password_hash = $2, session_version = session_version + 1 WHERE id = $1`,
      [req.params.id, await hashPassword(req.body.password)]);
    if (!rowCount) return res.status(404).json({ error: "見つかりません" });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// ======================= 名刺 =======================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)),
});

function pickFields(src) {
  const out = {};
  for (const f of FIELDS) out[f] = typeof src?.[f] === "string" ? src[f].trim().slice(0, 2000) : "";
  return out;
}
function pickTags(src) {
  if (!Array.isArray(src?.tags)) return [];
  const seen = new Set();
  for (const t of src.tags) {
    const v = String(t).trim().replace(/^#/, "").slice(0, 40);
    if (v) seen.add(v);
  }
  return [...seen].slice(0, 20);
}
// 一覧で返す列。my_note はログイン中の本人のメモだけ
const CARD_SELECT = `
  SELECT c.id, ${FIELDS.map((f) => "c." + f).join(", ")}, c.tags, (c.image IS NOT NULL) AS has_image,
         c.created_at, c.updated_at, c.created_by, c.created_by_name, COALESCE(n.note, '') AS my_note
  FROM cards c LEFT JOIN private_notes n ON n.card_id = c.id AND n.user_id = $1`;

async function getCard(id, userId) {
  const { rows } = await pool.query(`${CARD_SELECT} WHERE c.id = $2`, [userId, id]);
  return rows[0];
}
async function saveMyNote(userId, cardId, note) {
  if (typeof note !== "string") return;
  const v = note.trim().slice(0, 4000);
  if (v) {
    await pool.query(
      `INSERT INTO private_notes (user_id, card_id, note) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, card_id) DO UPDATE SET note = EXCLUDED.note, updated_at = now()`, [userId, cardId, v]);
  } else {
    await pool.query(`DELETE FROM private_notes WHERE user_id = $1 AND card_id = $2`, [userId, cardId]);
  }
}

// ---- 一覧 ----
app.get("/api/cards", async (req, res, next) => {
  try {
    const { rows } = await pool.query(`${CARD_SELECT} ORDER BY c.created_at DESC`, [req.user.id]);
    res.json(rows);
  } catch (e) { next(e); }
});

// ---- 画像 ----
app.get("/api/cards/:id/image", async (req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT image, image_type FROM cards WHERE id = $1", [req.params.id]);
    if (!rows[0]?.image) return res.status(404).end();
    res.set("Content-Type", rows[0].image_type || "image/jpeg");
    res.set("Cache-Control", "private, max-age=86400");
    res.send(rows[0].image);
  } catch (e) { next(e); }
});

// ---- 新規登録（multipart: image + data(JSON文字列)）----
app.post("/api/cards", upload.single("image"), async (req, res, next) => {
  try {
    let data = {};
    try { data = JSON.parse(req.body.data || "{}"); } catch { return res.status(400).json({ error: "data が不正です" }); }
    const f = pickFields(data);
    if (!f.name && !f.company) return res.status(400).json({ error: "会社名か氏名のどちらかを入力してください" });
    const id = crypto.randomUUID();
    const cols = ["id", ...FIELDS, "tags", "image", "image_type", "created_by", "created_by_name"];
    const vals = [id, ...FIELDS.map((k) => f[k]), pickTags(data), req.file?.buffer || null, req.file?.mimetype || null,
      req.user.id, req.user.display_name];
    const ph = cols.map((_, i) => `$${i + 1}`).join(", ");
    await pool.query(`INSERT INTO cards (${cols.join(", ")}) VALUES (${ph})`, vals);
    await saveMyNote(req.user.id, id, data.my_note);
    res.status(201).json(await getCard(id, req.user.id));
  } catch (e) { next(e); }
});

// ---- 更新 ----
app.put("/api/cards/:id", async (req, res, next) => {
  try {
    const f = pickFields(req.body);
    if (!f.name && !f.company) return res.status(400).json({ error: "会社名か氏名のどちらかを入力してください" });
    const sets = FIELDS.map((k, i) => `${k} = $${i + 2}`).join(", ");
    const tagParam = FIELDS.length + 2;
    const { rowCount } = await pool.query(
      `UPDATE cards SET ${sets}, tags = $${tagParam}, updated_at = now() WHERE id = $1`,
      [req.params.id, ...FIELDS.map((k) => f[k]), pickTags(req.body)]
    );
    if (!rowCount) return res.status(404).json({ error: "見つかりません" });
    await saveMyNote(req.user.id, req.params.id, req.body.my_note);
    res.json(await getCard(req.params.id, req.user.id));
  } catch (e) { next(e); }
});

// ---- 写真の差し替え（multipart: image）----
app.put("/api/cards/:id/image", upload.single("image"), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: "画像がありません（JPEG・PNG・WebP・GIF）" });
    const { rowCount } = await pool.query(
      `UPDATE cards SET image = $2, image_type = $3, updated_at = now() WHERE id = $1`,
      [req.params.id, req.file.buffer, req.file.mimetype]
    );
    if (!rowCount) return res.status(404).json({ error: "見つかりません" });
    res.json(await getCard(req.params.id, req.user.id));
  } catch (e) { next(e); }
});

// ---- 削除 ----
app.delete("/api/cards/:id", async (req, res, next) => {
  try {
    await pool.query("DELETE FROM cards WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) { next(e); }
});

// ---- 名刺の読み取り（Gemini API）----
const OCR_PROMPT = `添付画像は名刺の写真です。印刷されている内容を正確に読み取り、次のキーを持つJSONオブジェクトだけを返してください。前置きやコードブロックは不要です。
{"company":"","department":"","title":"","name":"","name_kana":"","phone":"","mobile":"","fax":"","email":"","address":"","url":""}
ルール:
- company: 会社・団体名（ロゴ内の社名も可）。
- department: 部署名。複数行なら半角スペースで連結。
- title: 役職・肩書。
- name: 氏名。姓と名の間は半角スペース1つ。
- name_kana: ふりがなやローマ字表記があればカタカナで（例: ヤマダ タロウ）。無ければ空文字。
- phone: 代表・直通の電話番号（ハイフンは名刺の表記どおり）。mobile: 携帯番号。fax: FAX番号。
- email, url: 記載どおり。address: 郵便番号を含む住所。
- 英語の名刺は英語のまま。読み取れない・記載のない項目は空文字。推測で補わない。
- 名刺が写っていない場合は全項目を空文字にする。`;

app.post("/api/ocr", upload.single("image"), async (req, res, next) => {
  try {
    if (!process.env.GEMINI_API_KEY) return res.status(503).json({ error: "GEMINI_API_KEY が設定されていません" });
    if (!req.file) return res.status(400).json({ error: "画像がありません（JPEG・PNG・WebP・GIF）" });

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(MODEL)}:generateContent`;
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-goog-api-key": process.env.GEMINI_API_KEY,
      },
      body: JSON.stringify({
        contents: [{
          role: "user",
          parts: [
            { inline_data: { mime_type: req.file.mimetype, data: req.file.buffer.toString("base64") } },
            { text: OCR_PROMPT },
          ],
        }],
        generationConfig: {
          responseMimeType: "application/json", // JSONだけを返させる
          temperature: 0,
          maxOutputTokens: 4096,                // 思考トークンも含むため余裕を持たせる
        },
      }),
    });
    if (!r.ok) {
      const detail = await r.text();
      console.error("Gemini API error", r.status, detail);
      const msg = r.status === 429 ? "読み取りの回数が上限に達しました。少し待ってから再試行してください。" : "読み取りに失敗しました。";
      return res.status(502).json({ error: msg });
    }
    const body = await r.json();
    const text = (body.candidates?.[0]?.content?.parts || []).map((p) => p.text || "").join("");
    const m = text.match(/\{[\s\S]*\}/);
    let parsed = {};
    try { parsed = m ? JSON.parse(m[0]) : {}; } catch { parsed = {}; }
    const out = {};
    for (const f of OCR_FIELDS) out[f] = typeof parsed[f] === "string" ? parsed[f].trim() : "";
    res.json(out);
  } catch (e) { next(e); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return res.status(400).json({ error: "画像が大きすぎます（8MBまで）" });
  res.status(500).json({ error: "サーバーでエラーが発生しました" });
});

migrate()
  .then(() => app.listen(PORT, () => console.log(`名刺帳: http://localhost:${PORT}`)))
  .catch((e) => { console.error("DB初期化に失敗しました", e); process.exit(1); });
