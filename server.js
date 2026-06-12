// ============================================================
// DinShare サーバー
// アカウント（ユーザーネーム＋パスワードのみ）・投稿・コメント・
// リアクション・プレイリスト・ファイルアップロード対応
// ============================================================
const express = require('express');
const { DatabaseSync } = require('node:sqlite'); // Node.js標準内蔵SQLite (v22以降)
const bcrypt = require('bcryptjs');
const multer = require('multer');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- アップロード先フォルダ ----------
const DATA_DIR = process.env.DATA_DIR || __dirname;
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- データベース ----------
const db = new DatabaseSync(path.join(DATA_DIR, 'dinshare.db'));
db.exec('PRAGMA journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,            -- text / photo / video / voice / music
  title TEXT DEFAULT '',
  text TEXT DEFAULT '',
  file_path TEXT,
  likes INTEGER DEFAULT 0,
  kindas INTEGER DEFAULT 0,
  views INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS playlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now','localtime')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS playlist_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  playlist_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  position INTEGER DEFAULT 0,
  FOREIGN KEY (playlist_id) REFERENCES playlists(id) ON DELETE CASCADE,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);
`);

// ---------- ミドルウェア ----------
app.use(express.json());
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 } // 30日
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// ---------- multer（ファイルアップロード設定） ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + crypto.randomBytes(6).toString('hex') + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 } // 200MB上限
});

// ---------- 認証ヘルパー ----------
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'ログインが必要です' });
  }
  next();
}

// 絵文字カウント（コメント規則用）
function countUniqueEmoji(text) {
  const matches = [...text.matchAll(/\p{Emoji_Presentation}|\p{Extended_Pictographic}/gu)];
  return new Set(matches.map(m => m[0])).size;
}

// ============================================================
// 認証API
// ============================================================

// アカウント登録（ユーザーネーム＋パスワードのみ）
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザーネームとパスワードを入力してください' });
  }
  if (username.length < 2 || username.length > 20) {
    return res.status(400).json({ error: 'ユーザーネームは2〜20文字にしてください' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'パスワードは6文字以上にしてください' });
  }
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) {
    return res.status(409).json({ error: 'このユーザーネームは既に使われています' });
  }
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
  req.session.userId = result.lastInsertRowid;
  req.session.username = username;
  res.json({ ok: true, username });
});

// ログイン
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'ユーザーネームまたはパスワードが違います' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ ok: true, username: user.username });
});

// ログアウト
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ログイン状態確認
app.get('/api/me', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.json({ loggedIn: false });
  }
});

// ============================================================
// 投稿API
// ============================================================

// 投稿一覧（検索・タイプフィルタ対応）
app.get('/api/posts', (req, res) => {
  const { q, type } = req.query;
  let sql = `
    SELECT p.*, u.username,
      (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
    FROM posts p JOIN users u ON p.user_id = u.id
  `;
  const conds = [];
  const params = [];
  if (type && type !== 'all') { conds.push('p.type = ?'); params.push(type); }
  if (q) {
    conds.push('(p.text LIKE ? OR p.title LIKE ? OR u.username LIKE ?)');
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  if (conds.length) sql += ' WHERE ' + conds.join(' AND ');
  sql += ' ORDER BY p.id DESC LIMIT 100';
  const posts = db.prepare(sql).all(...params);
  const isAdmin = req.session.username === process.env.ADMIN_USERNAME;
  res.json(posts.map(p => ({ ...p, isMine: p.user_id === req.session.userId || isAdmin })));
});

// 投稿作成（要ログイン）
app.post('/api/posts', requireLogin, upload.single('file'), (req, res) => {
  const { type, title = '', text = '' } = req.body;
  const validTypes = ['text', 'photo', 'video', 'voice', 'music'];
  if (!validTypes.includes(type)) {
    return res.status(400).json({ error: '不正な投稿タイプです' });
  }
  if (type === 'text' && !text.trim()) {
    return res.status(400).json({ error: 'テキストを入力してください' });
  }
  if (type !== 'text' && !req.file) {
    return res.status(400).json({ error: 'ファイルを選択してください' });
  }
  const filePath = req.file ? '/uploads/' + req.file.filename : null;
  const result = db.prepare(
    'INSERT INTO posts (user_id, type, title, text, file_path) VALUES (?, ?, ?, ?, ?)'
  ).run(req.session.userId, type, title.slice(0, 80), text.slice(0, 500), filePath);
  res.json({ ok: true, id: result.lastInsertRowid });
});

// 投稿削除（本人または管理者）
app.delete('/api/posts/:id', requireLogin, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: '投稿が見つかりません' });
  const isAdmin = req.session.username === process.env.ADMIN_USERNAME;
  if (post.user_id !== req.session.userId && !isAdmin) {
    return res.status(403).json({ error: '自分の投稿のみ削除できます' });
  }
  // ファイルも削除
  if (post.file_path) {
    const fp = path.join(DATA_DIR, post.file_path);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
  db.prepare('DELETE FROM comments WHERE post_id = ?').run(post.id);
  db.prepare('DELETE FROM playlist_items WHERE post_id = ?').run(post.id);
  db.prepare('DELETE FROM posts WHERE id = ?').run(post.id);
  res.json({ ok: true });
});

// リアクション（何回でも押せる・ログイン不要）
app.post('/api/posts/:id/react', (req, res) => {
  const { kind } = req.body; // 'like' or 'kinda'
  const col = kind === 'like' ? 'likes' : kind === 'kinda' ? 'kindas' : null;
  if (!col) return res.status(400).json({ error: '不正なリアクションです' });
  const result = db.prepare(`UPDATE posts SET ${col} = ${col} + 1 WHERE id = ?`).run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: '投稿が見つかりません' });
  const post = db.prepare('SELECT likes, kindas FROM posts WHERE id = ?').get(req.params.id);
  res.json({ ok: true, likes: post.likes, kindas: post.kindas });
});

// 視聴回数カウント
app.post('/api/posts/:id/view', (req, res) => {
  db.prepare('UPDATE posts SET views = views + 1 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ============================================================
// コメントAPI（絵文字3種類以上ルール）
// ============================================================
app.get('/api/posts/:id/comments', (req, res) => {
  const comments = db.prepare(`
    SELECT c.*, u.username FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.post_id = ? ORDER BY c.id ASC
  `).all(req.params.id);
  const isAdmin = req.session.username === process.env.ADMIN_USERNAME;
  res.json(comments.map(c => ({
    ...c,
    canDelete: c.user_id === req.session.userId || isAdmin
  })));
});

app.post('/api/posts/:id/comments', requireLogin, (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) {
    return res.status(400).json({ error: 'コメントを入力してください' });
  }
  // サーバー側でも絵文字ルールを検証
  if (countUniqueEmoji(text) < 3) {
    return res.status(400).json({ error: '絵文字を3種類以上使ってください 🎉✨🙏' });
  }
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: '投稿が見つかりません' });
  db.prepare('INSERT INTO comments (post_id, user_id, text) VALUES (?, ?, ?)')
    .run(req.params.id, req.session.userId, text.slice(0, 300));
  res.json({ ok: true });
});

// コメント削除（本人または管理者）
app.delete('/api/comments/:id', requireLogin, (req, res) => {
  const comment = db.prepare('SELECT * FROM comments WHERE id = ?').get(req.params.id);
  if (!comment) return res.status(404).json({ error: 'コメントが見つかりません' });
  const isAdmin = req.session.username === process.env.ADMIN_USERNAME;
  if (comment.user_id !== req.session.userId && !isAdmin) {
    return res.status(403).json({ error: '自分のコメントのみ削除できます' });
  }
  db.prepare('DELETE FROM comments WHERE id = ?').run(comment.id);
  res.json({ ok: true });
});

// ============================================================
// プレイリストAPI（要ログイン・自分のものだけ）
// ============================================================
app.get('/api/playlists', requireLogin, (req, res) => {
  const lists = db.prepare(`
    SELECT pl.*, (SELECT COUNT(*) FROM playlist_items pi WHERE pi.playlist_id = pl.id) AS item_count
    FROM playlists pl WHERE pl.user_id = ? ORDER BY pl.id DESC
  `).all(req.session.userId);
  res.json(lists);
});

app.post('/api/playlists', requireLogin, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: '名前を入力してください' });
  const result = db.prepare('INSERT INTO playlists (user_id, name) VALUES (?, ?)')
    .run(req.session.userId, name.slice(0, 50));
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.delete('/api/playlists/:id', requireLogin, (req, res) => {
  const pl = db.prepare('SELECT * FROM playlists WHERE id = ?').get(req.params.id);
  if (!pl || pl.user_id !== req.session.userId) {
    return res.status(403).json({ error: '権限がありません' });
  }
  db.prepare('DELETE FROM playlist_items WHERE playlist_id = ?').run(pl.id);
  db.prepare('DELETE FROM playlists WHERE id = ?').run(pl.id);
  res.json({ ok: true });
});

app.post('/api/playlists/:id/items', requireLogin, (req, res) => {
  const pl = db.prepare('SELECT * FROM playlists WHERE id = ?').get(req.params.id);
  if (!pl || pl.user_id !== req.session.userId) {
    return res.status(403).json({ error: '権限がありません' });
  }
  const { postId } = req.body;
  const exists = db.prepare('SELECT id FROM playlist_items WHERE playlist_id = ? AND post_id = ?')
    .get(pl.id, postId);
  if (exists) return res.status(409).json({ error: 'すでに追加されています' });
  db.prepare('INSERT INTO playlist_items (playlist_id, post_id) VALUES (?, ?)').run(pl.id, postId);
  res.json({ ok: true });
});

app.get('/api/playlists/:id/items', requireLogin, (req, res) => {
  const pl = db.prepare('SELECT * FROM playlists WHERE id = ?').get(req.params.id);
  if (!pl || pl.user_id !== req.session.userId) {
    return res.status(403).json({ error: '権限がありません' });
  }
  const items = db.prepare(`
    SELECT p.*, u.username FROM playlist_items pi
    JOIN posts p ON pi.post_id = p.id
    JOIN users u ON p.user_id = u.id
    WHERE pi.playlist_id = ? ORDER BY pi.position, pi.id
  `).all(pl.id);
  res.json(items);
});
// ---------- 投稿の共有用ページ（OGP対応） ----------
app.get('/post/:id', (req, res) => {
  const post = db.prepare(`
    SELECT p.*, u.username FROM posts p
    JOIN users u ON p.user_id = u.id WHERE p.id = ?
  `).get(req.params.id);
  if (!post) return res.redirect('/');
  const title = (post.title || post.text || 'DinShareの投稿').slice(0, 60);
  const desc = (post.text || `${post.username}さんの投稿`).slice(0, 120);
  res.send(`<!DOCTYPE html>
<html lang="ja"><head>
<meta charset="UTF-8">
<title>${title} - DinShare</title>
<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
<meta property="og:type" content="website">
<script>location.href='/?post=' + ${post.id};</script>
</head><body></body></html>`);
});

// ---------- 起動 ----------
app.listen(PORT, () => {
  console.log(`🚀 DinShare サーバー起動: http://localhost:${PORT}`);
});
