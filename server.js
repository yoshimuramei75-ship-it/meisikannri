import express from "express";
import multer from "multer";
import pg from "pg";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const MODEL = process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5";
const FIELDS = ["company", "department", "title", "name", "name_kana", "phone", "mobile", "fax", "email", "address", "url", "met_place", "memo"];
const OCR_FIELDS = FIELDS.filter((f) => f !== "memo" && f !== "met_place");

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL が設定されていません");
  process.exit(1);
}

// Render の内部接続は SSL 不要。外部接続URLを使う場合は PGSSL=true を設定。
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

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
}

const app = express();
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => res.send("ok"));

// ---- Basic 認証（APP_USER / APP_PASSWORD が設定されていれば有効）----
const AUTH_USER = process.env.APP_USER;
const AUTH_PASS = process.env.APP_PASSWORD;
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}
app.use((req, res, next) => {
  if (!AUTH_USER || !AUTH_PASS) return next();
  const [scheme, encoded] = (req.headers.authorization || "").split(" ");
  if (scheme === "Basic" && encoded) {
    const decoded = Buffer.from(encoded, "base64").toString();
    const i = decoded.indexOf(":");
    if (i >= 0 && safeEqual(decoded.slice(0, i), AUTH_USER) && safeEqual(decoded.slice(i + 1), AUTH_PASS)) return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="meishi", charset="UTF-8"').status(401).send("ログインが必要です");
});

app.use(express.json({ limit: "200kb" }));
app.use(express.static(path.join(__dirname, "public")));

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
const LIST_COLS = `id, ${FIELDS.join(", ")}, tags, (image IS NOT NULL) AS has_image, created_at, updated_at`;

// ---- 一覧 ----
app.get("/api/cards", async (_req, res, next) => {
  try {
    const { rows } = await pool.query(`SELECT ${LIST_COLS} FROM cards ORDER BY created_at DESC`);
    res.json(rows);
  } catch (e) { next(e); }
});

// ---- 画像 ----
app.get("/api/cards/:id/image", async (req, res, next) => {
  try {
    const { rows } = await pool.query("SELECT image, image_type, updated_at FROM cards WHERE id = $1", [req.params.id]);
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
    const cols = ["id", ...FIELDS, "tags", "image", "image_type"];
    const vals = [id, ...FIELDS.map((k) => f[k]), pickTags(data), req.file?.buffer || null, req.file?.mimetype || null];
    const ph = cols.map((_, i) => `$${i + 1}`).join(", ");
    const { rows } = await pool.query(`INSERT INTO cards (${cols.join(", ")}) VALUES (${ph}) RETURNING ${LIST_COLS}`, vals);
    res.status(201).json(rows[0]);
  } catch (e) { next(e); }
});

// ---- 更新 ----
app.put("/api/cards/:id", async (req, res, next) => {
  try {
    const f = pickFields(req.body);
    if (!f.name && !f.company) return res.status(400).json({ error: "会社名か氏名のどちらかを入力してください" });
    const sets = FIELDS.map((k, i) => `${k} = $${i + 2}`).join(", ");
    const tagParam = FIELDS.length + 2;
    const { rows } = await pool.query(
      `UPDATE cards SET ${sets}, tags = $${tagParam}, updated_at = now() WHERE id = $1 RETURNING ${LIST_COLS}`,
      [req.params.id, ...FIELDS.map((k) => f[k]), pickTags(req.body)]
    );
    if (!rows[0]) return res.status(404).json({ error: "見つかりません" });
    res.json(rows[0]);
  } catch (e) { next(e); }
});

// ---- 削除 ----
app.delete("/api/cards/:id", async (req, res, next) => {
  try {
    await pool.query("DELETE FROM cards WHERE id = $1", [req.params.id]);
    res.status(204).end();
  } catch (e) { next(e); }
});

// ---- 名刺の読み取り（Claude API）----
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
    if (!process.env.ANTHROPIC_API_KEY) return res.status(503).json({ error: "ANTHROPIC_API_KEY が設定されていません" });
    if (!req.file) return res.status(400).json({ error: "画像がありません（JPEG・PNG・WebP・GIF）" });

    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1024,
        messages: [{
          role: "user",
          content: [
            { type: "image", source: { type: "base64", media_type: req.file.mimetype, data: req.file.buffer.toString("base64") } },
            { type: "text", text: OCR_PROMPT },
          ],
        }],
      }),
    });
    if (!r.ok) {
      const detail = await r.text();
      console.error("Claude API error", r.status, detail);
      const msg = r.status === 429 ? "読み取りの回数が上限に達しました。少し待ってから再試行してください。" : "読み取りに失敗しました。";
      return res.status(502).json({ error: msg });
    }
    const body = await r.json();
    const text = (body.content || []).filter((c) => c.type === "text").map((c) => c.text).join("");
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
