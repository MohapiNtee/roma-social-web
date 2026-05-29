const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DB_FILE = path.join(ROOT, "roma-social.sqlite");
const LEGACY_JSON = path.join(ROOT, "social-data.json");
const SESSION_DAYS = 14;

const db = new DatabaseSync(DB_FILE);
db.exec("PRAGMA foreign_keys = ON");
db.exec("PRAGMA journal_mode = WAL");

function nowIso() {
  return new Date().toISOString();
}

function readText(fileName) {
  try {
    return fs.readFileSync(path.join(ROOT, fileName), "utf8");
  } catch {
    return "";
  }
}

function splitLines(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function run(sql, params = []) {
  return db.prepare(sql).run(...params);
}

function get(sql, params = []) {
  return db.prepare(sql).get(...params);
}

function all(sql, params = []) {
  return db.prepare(sql).all(...params);
}

function createSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS profiles (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      full_name TEXT NOT NULL,
      email TEXT,
      address TEXT,
      occupation TEXT,
      course TEXT,
      phone1 TEXT,
      phone2 TEXT,
      dob_day TEXT,
      dob_month TEXT,
      dob_year TEXT,
      bio TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS posts (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS post_likes (
      post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      PRIMARY KEY (post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS friendships (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      PRIMARY KEY (user_id, friend_id),
      CHECK (user_id <> friend_id)
    );

    CREATE TABLE IF NOT EXISTS friend_requests (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL,
      UNIQUE (from_user_id, to_user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL,
      read_at TEXT
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      to_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      from_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      type TEXT NOT NULL,
      text TEXT NOT NULL,
      read_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(from_user_id, to_user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(to_user_id, created_at DESC);
  `);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, "sha256").toString("hex");
  return `pbkdf2$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!stored.startsWith("pbkdf2$")) return password === stored;
  const [, salt, expected] = stored.split("$");
  const actual = crypto.pbkdf2Sync(String(password), salt, 120000, 32, "sha256").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function parseLegacyFromText() {
  const logins = {};
  for (const line of splitLines(readText("Login.txt"))) {
    const [username, password] = line.split(/\s+/);
    if (username && password) logins[username] = password;
  }

  const users = Object.entries(logins).map(([username, password], index) => ({
    id: crypto.randomUUID(),
    username,
    password,
    role: index === 0 ? "admin" : "user",
    status: "active",
    profile: {
      fullName: username,
      email: "",
      address: "",
      occupation: "",
      course: "",
      phone1: "",
      phone2: "",
      dob: { day: "", month: "", year: "" },
      bio: "Building connections on Roma Social."
    }
  }));

  for (const line of splitLines(readText("Users.txt"))) {
    const [username, raw] = line.split(":");
    const user = users.find((item) => item.username === username);
    if (!user || !raw) continue;
    const parts = raw.split("~");
    user.profile = {
      fullName: parts[1] || username,
      email: parts[2] || "",
      address: parts[3] || "",
      occupation: parts[4] || "",
      course: parts[10] || "",
      phone1: parts[5] || "",
      phone2: parts[6] || "",
      dob: { day: parts[7] || "", month: parts[8] || "", year: parts[9] || "" },
      bio: "Building connections on Roma Social."
    };
  }

  const posts = splitLines(readText("Posts.txt")).map((line) => {
    const [username, content, timestamp] = line.split("~");
    return { username, content, createdAt: timestamp ? new Date(timestamp).toISOString() : nowIso() };
  });

  const friendships = [];
  for (const line of splitLines(readText("Friends.txt"))) {
    const [username, ...friends] = line.split("~").filter(Boolean);
    for (const friend of friends) friendships.push([username, friend]);
  }

  return { users, posts, friendships, messages: [] };
}

function parseLegacyJson() {
  if (!fs.existsSync(LEGACY_JSON)) return parseLegacyFromText();
  const legacy = JSON.parse(fs.readFileSync(LEGACY_JSON, "utf8"));
  const users = (legacy.users || []).map((user, index) => ({
    id: user.id || crypto.randomUUID(),
    username: user.username,
    password: user.password || "password",
    role: index === 0 ? "admin" : user.role || "user",
    status: user.status || "active",
    profile: {
      fullName: user.profile?.fullName || user.username,
      email: user.profile?.email || "",
      address: user.profile?.address || "",
      occupation: user.profile?.occupation || "",
      course: user.profile?.course || "",
      phone1: user.profile?.phone1 || "",
      phone2: user.profile?.phone2 || "",
      dob: user.profile?.dob || { day: "", month: "", year: "" },
      bio: user.profile?.bio || "Building connections on Roma Social."
    }
  }));
  const posts = (legacy.posts || []).map((post) => ({
    username: post.username,
    content: post.content,
    createdAt: post.createdAt || nowIso(),
    likes: post.likes || [],
    comments: post.comments || []
  }));
  const friendships = [];
  Object.entries(legacy.friends || {}).forEach(([username, friends]) => {
    for (const friend of friends) friendships.push([username, friend]);
  });
  const messages = (legacy.messages || []).map((message) => ({
    from: message.from,
    to: message.to,
    body: message.body,
    createdAt: message.createdAt || nowIso()
  }));
  return { users, posts, friendships, messages };
}

function insertUser(user) {
  run(
    "INSERT OR IGNORE INTO users (id, username, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    [user.id, user.username, hashPassword(user.password), user.role, user.status, nowIso()]
  );
  run(
    `INSERT OR IGNORE INTO profiles
      (user_id, full_name, email, address, occupation, course, phone1, phone2, dob_day, dob_month, dob_year, bio, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      user.id,
      user.profile.fullName,
      user.profile.email,
      user.profile.address,
      user.profile.occupation,
      user.profile.course,
      user.profile.phone1,
      user.profile.phone2,
      user.profile.dob?.day || "",
      user.profile.dob?.month || "",
      user.profile.dob?.year || "",
      user.profile.bio,
      nowIso()
    ]
  );
}

function migrateInitialData() {
  const count = get("SELECT COUNT(*) AS count FROM users").count;
  if (count > 0) return;

  const legacy = parseLegacyJson();
  const byName = new Map();
  for (const user of legacy.users) {
    insertUser(user);
    byName.set(user.username, user.id);
  }

  if (!byName.has("admin")) {
    const admin = {
      id: crypto.randomUUID(),
      username: "admin",
      password: "admin123",
      role: "admin",
      status: "active",
      profile: {
        fullName: "Roma Social Admin",
        email: "",
        address: "",
        occupation: "Administrator",
        course: "",
        phone1: "",
        phone2: "",
        dob: { day: "", month: "", year: "" },
        bio: "Platform management account."
      }
    };
    insertUser(admin);
    byName.set(admin.username, admin.id);
  }

  for (const post of legacy.posts) {
    const userId = byName.get(post.username);
    if (!userId || !post.content) continue;
    const postId = crypto.randomUUID();
    run("INSERT INTO posts (id, user_id, content, created_at) VALUES (?, ?, ?, ?)", [postId, userId, post.content, post.createdAt]);
    for (const likeName of post.likes || []) {
      const likeUserId = byName.get(likeName);
      if (likeUserId) run("INSERT OR IGNORE INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, ?)", [postId, likeUserId, nowIso()]);
    }
    for (const comment of post.comments || []) {
      const commentUserId = byName.get(comment.username);
      if (commentUserId) {
        run("INSERT INTO comments (id, post_id, user_id, text, created_at) VALUES (?, ?, ?, ?, ?)", [
          comment.id || crypto.randomUUID(),
          postId,
          commentUserId,
          comment.text,
          comment.createdAt || nowIso()
        ]);
      }
    }
  }

  for (const [a, b] of legacy.friendships) {
    const userA = byName.get(a);
    const userB = byName.get(b);
    if (userA && userB && userA !== userB) {
      run("INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?, ?, ?)", [userA, userB, nowIso()]);
      run("INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?, ?, ?)", [userB, userA, nowIso()]);
    }
  }

  for (const message of legacy.messages) {
    const from = byName.get(message.from);
    const to = byName.get(message.to);
    if (from && to && message.body) {
      run("INSERT INTO messages (id, from_user_id, to_user_id, body, created_at) VALUES (?, ?, ?, ?, ?)", [
        crypto.randomUUID(),
        from,
        to,
        message.body,
        message.createdAt
      ]);
    }
  }
}

function profileSelect(userAlias = "u", profileAlias = "p") {
  return `
    ${userAlias}.id,
    ${userAlias}.username,
    ${userAlias}.role,
    ${userAlias}.status,
    ${userAlias}.created_at AS createdAt,
    ${profileAlias}.full_name AS fullName,
    ${profileAlias}.email,
    ${profileAlias}.address,
    ${profileAlias}.occupation,
    ${profileAlias}.course,
    ${profileAlias}.phone1,
    ${profileAlias}.phone2,
    ${profileAlias}.dob_day AS dobDay,
    ${profileAlias}.dob_month AS dobMonth,
    ${profileAlias}.dob_year AS dobYear,
    ${profileAlias}.bio
  `;
}

function rowToPublicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    status: row.status,
    profile: {
      username: row.username,
      fullName: row.fullName || row.username,
      email: row.email || "",
      address: row.address || "",
      occupation: row.occupation || "",
      course: row.course || "",
      phone1: row.phone1 || "",
      phone2: row.phone2 || "",
      dob: { day: row.dobDay || "", month: row.dobMonth || "", year: row.dobYear || "" },
      bio: row.bio || "",
      joinedAt: row.createdAt
    }
  };
}

function getUserByUsername(username) {
  return get(
    `SELECT ${profileSelect()} FROM users u JOIN profiles p ON p.user_id = u.id WHERE u.username = ?`,
    [username]
  );
}

function getUserById(id) {
  return get(`SELECT ${profileSelect()} FROM users u JOIN profiles p ON p.user_id = u.id WHERE u.id = ?`, [id]);
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function sendError(res, status, message) {
  sendJson(res, status, { error: message });
}

function parseCookies(req) {
  const cookies = {};
  const raw = req.headers.cookie || "";
  raw.split(";").forEach((part) => {
    const [key, value] = part.trim().split("=");
    if (key) cookies[key] = decodeURIComponent(value || "");
  });
  return cookies;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error("Request body is too large."));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON."));
      }
    });
  });
}

function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  run("INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", [tokenHash(token), userId, expires, nowIso()]);
  res.setHeader("Set-Cookie", `session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`);
}

function currentUser(req) {
  const token = parseCookies(req).session;
  if (!token) return null;
  const session = get("SELECT user_id AS userId FROM sessions WHERE token_hash = ? AND expires_at > ?", [tokenHash(token), nowIso()]);
  if (!session) return null;
  const user = getUserById(session.userId);
  return user && user.status === "active" ? user : null;
}

function requireUser(req, res) {
  const user = currentUser(req);
  if (!user) sendError(res, 401, "Please log in first.");
  return user;
}

function requireAdmin(req, res) {
  const user = requireUser(req, res);
  if (!user) return null;
  if (user.role !== "admin") {
    sendError(res, 403, "Admin access required.");
    return null;
  }
  return user;
}

function areFriends(a, b) {
  return Boolean(get("SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?", [a, b]));
}

function addFriendship(a, b) {
  run("INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?, ?, ?)", [a, b, nowIso()]);
  run("INSERT OR IGNORE INTO friendships (user_id, friend_id, created_at) VALUES (?, ?, ?)", [b, a, nowIso()]);
}

function removeFriendship(a, b) {
  run("DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)", [a, b, b, a]);
}

function createNotification(toUserId, fromUserId, type, text) {
  if (!toUserId || toUserId === fromUserId) return;
  run(
    "INSERT INTO notifications (id, to_user_id, from_user_id, type, text, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    [crypto.randomUUID(), toUserId, fromUserId || null, type, text, nowIso()]
  );
}

function decoratePost(post, viewerId) {
  const postId = post.postId || post.id;
  const comments = all(
    `SELECT c.id, c.text, c.created_at AS createdAt, u.username
     FROM comments c JOIN users u ON u.id = c.user_id
     WHERE c.post_id = ? ORDER BY c.created_at ASC`,
    [postId]
  );
  return {
    id: postId,
    username: post.username,
    content: post.content,
    createdAt: post.createdAt,
    author: rowToPublicUser(post),
    likes: all("SELECT u.username FROM post_likes l JOIN users u ON u.id = l.user_id WHERE l.post_id = ?", [postId]).map((row) => row.username),
    comments,
    likedByMe: Boolean(get("SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?", [postId, viewerId]))
  };
}

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host}`).pathname);
  const requested = urlPath === "/" ? "index.html" : urlPath.slice(1);
  const filePath = path.normalize(path.join(PUBLIC_DIR, requested));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  fs.readFile(filePath, (error, content) => {
    if (error) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    const types = { ".html": "text/html", ".css": "text/css", ".js": "application/javascript" };
    res.writeHead(200, { "Content-Type": types[path.extname(filePath).toLowerCase()] || "application/octet-stream" });
    res.end(content);
  });
}

async function handleApi(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const route = `${req.method} ${url.pathname}`;

  try {
    if (route === "POST /api/login") {
      const body = await readBody(req);
      const user = get("SELECT * FROM users WHERE username = ? COLLATE NOCASE", [String(body.username || "").trim()]);
      if (!user || user.status !== "active" || !verifyPassword(body.password || "", user.password_hash)) {
        return sendError(res, 401, "Invalid username or password.");
      }
      createSession(res, user.id);
      return sendJson(res, 200, { user: rowToPublicUser(getUserById(user.id)) });
    }

    if (route === "POST /api/register") {
      const body = await readBody(req);
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) return sendError(res, 400, "Use 3-24 letters, numbers, or underscores for the username.");
      if (password.length < 8) return sendError(res, 400, "Password must be at least 8 characters.");
      if (get("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", [username])) return sendError(res, 409, "That username is already taken.");
      const userId = crypto.randomUUID();
      run("INSERT INTO users (id, username, password_hash, role, status, created_at) VALUES (?, ?, ?, 'user', 'active', ?)", [
        userId,
        username,
        hashPassword(password),
        nowIso()
      ]);
      run(
        `INSERT INTO profiles (user_id, full_name, email, address, occupation, course, phone1, phone2, dob_day, dob_month, dob_year, bio, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, '', '', '', '', '', ?, ?)`,
        [
          userId,
          String(body.fullName || username).trim(),
          String(body.email || "").trim(),
          String(body.address || "").trim(),
          String(body.occupation || "").trim(),
          String(body.course || "").trim(),
          String(body.bio || "Building connections on Roma Social.").trim(),
          nowIso()
        ]
      );
      createSession(res, userId);
      return sendJson(res, 201, { user: rowToPublicUser(getUserById(userId)) });
    }

    if (route === "POST /api/logout") {
      const token = parseCookies(req).session;
      if (token) run("DELETE FROM sessions WHERE token_hash = ?", [tokenHash(token)]);
      res.setHeader("Set-Cookie", "session=; Max-Age=0; SameSite=Lax; Path=/");
      return sendJson(res, 200, { ok: true });
    }

    if (route === "GET /api/me") {
      const user = currentUser(req);
      return sendJson(res, 200, { user: rowToPublicUser(user) });
    }

    const adminStats = route === "GET /api/admin/stats";
    const adminUsers = route === "GET /api/admin/users";
    const adminUserAction = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (adminStats || adminUsers || adminUserAction) {
      const admin = requireAdmin(req, res);
      if (!admin) return;
      if (adminStats) {
        return sendJson(res, 200, {
          stats: {
            users: get("SELECT COUNT(*) AS count FROM users").count,
            posts: get("SELECT COUNT(*) AS count FROM posts").count,
            messages: get("SELECT COUNT(*) AS count FROM messages").count,
            pendingRequests: get("SELECT COUNT(*) AS count FROM friend_requests WHERE status = 'pending'").count
          }
        });
      }
      if (adminUsers) {
        return sendJson(res, 200, {
          users: all(`SELECT ${profileSelect()} FROM users u JOIN profiles p ON p.user_id = u.id ORDER BY u.created_at DESC`).map(rowToPublicUser)
        });
      }
      if (req.method === "PATCH" && adminUserAction) {
        const body = await readBody(req);
        const target = getUserById(adminUserAction[1]);
        if (!target) return sendError(res, 404, "User not found.");
        if (target.id === admin.id && body.status && body.status !== "active") return sendError(res, 400, "You cannot disable your own admin account.");
        if (target.id === admin.id && body.role && body.role !== "admin") return sendError(res, 400, "You cannot remove your own admin access.");
        if (body.status) run("UPDATE users SET status = ? WHERE id = ?", [body.status === "disabled" ? "disabled" : "active", target.id]);
        if (body.role && ["user", "admin"].includes(body.role)) run("UPDATE users SET role = ? WHERE id = ?", [body.role, target.id]);
        return sendJson(res, 200, { user: rowToPublicUser(getUserById(target.id)) });
      }
    }

    const user = requireUser(req, res);
    if (!user) return;

    if (route === "GET /api/feed") {
      const scope = url.searchParams.get("scope") || "all";
      const params = [];
      let where = "1 = 1";
      if (scope === "friends") {
        where = "p.user_id = ? OR p.user_id IN (SELECT friend_id FROM friendships WHERE user_id = ?)";
        params.push(user.id, user.id);
      }
      const posts = all(
        `SELECT p.id AS postId, p.content, p.created_at AS createdAt, ${profileSelect("u", "p2")}
         FROM posts p JOIN users u ON u.id = p.user_id JOIN profiles p2 ON p2.user_id = u.id
         WHERE ${where} ORDER BY p.created_at DESC`,
        params
      ).map((post) => decoratePost(post, user.id));
      return sendJson(res, 200, { posts });
    }

    if (route === "POST /api/posts") {
      const body = await readBody(req);
      const content = String(body.content || "").trim();
      if (!content) return sendError(res, 400, "Post cannot be empty.");
      const id = crypto.randomUUID();
      run("INSERT INTO posts (id, user_id, content, created_at) VALUES (?, ?, ?, ?)", [id, user.id, content, nowIso()]);
      const post = get(
        `SELECT p.id AS postId, p.content, p.created_at AS createdAt, ${profileSelect("u", "p2")}
         FROM posts p JOIN users u ON u.id = p.user_id JOIN profiles p2 ON p2.user_id = u.id WHERE p.id = ?`,
        [id]
      );
      return sendJson(res, 201, { post: decoratePost(post, user.id) });
    }

    const postLikeMatch = url.pathname.match(/^\/api\/posts\/([^/]+)\/like$/);
    if (req.method === "POST" && postLikeMatch) {
      const post = get("SELECT * FROM posts WHERE id = ?", [postLikeMatch[1]]);
      if (!post) return sendError(res, 404, "Post not found.");
      const existing = get("SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?", [post.id, user.id]);
      if (existing) {
        run("DELETE FROM post_likes WHERE post_id = ? AND user_id = ?", [post.id, user.id]);
      } else {
        run("INSERT INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, ?)", [post.id, user.id, nowIso()]);
        createNotification(post.user_id, user.id, "like", `${user.fullName} liked your post.`);
      }
      const decorated = get(
        `SELECT p.id AS postId, p.content, p.created_at AS createdAt, ${profileSelect("u", "p2")}
         FROM posts p JOIN users u ON u.id = p.user_id JOIN profiles p2 ON p2.user_id = u.id WHERE p.id = ?`,
        [post.id]
      );
      return sendJson(res, 200, { post: decoratePost(decorated, user.id) });
    }

    const postCommentMatch = url.pathname.match(/^\/api\/posts\/([^/]+)\/comments$/);
    if (req.method === "POST" && postCommentMatch) {
      const post = get("SELECT * FROM posts WHERE id = ?", [postCommentMatch[1]]);
      if (!post) return sendError(res, 404, "Post not found.");
      const body = await readBody(req);
      const text = String(body.text || "").trim();
      if (!text) return sendError(res, 400, "Comment cannot be empty.");
      run("INSERT INTO comments (id, post_id, user_id, text, created_at) VALUES (?, ?, ?, ?, ?)", [crypto.randomUUID(), post.id, user.id, text, nowIso()]);
      createNotification(post.user_id, user.id, "comment", `${user.fullName} commented on your post.`);
      const decorated = get(
        `SELECT p.id AS postId, p.content, p.created_at AS createdAt, ${profileSelect("u", "p2")}
         FROM posts p JOIN users u ON u.id = p.user_id JOIN profiles p2 ON p2.user_id = u.id WHERE p.id = ?`,
        [post.id]
      );
      return sendJson(res, 201, { post: decoratePost(decorated, user.id) });
    }

    if (route === "GET /api/users") {
      const rows = all(`SELECT ${profileSelect()} FROM users u JOIN profiles p ON p.user_id = u.id WHERE u.status = 'active' ORDER BY p.full_name`);
      const users = rows.map((row) => ({
        ...rowToPublicUser(row),
        isMe: row.id === user.id,
        isFriend: areFriends(user.id, row.id),
        outgoingRequest: Boolean(get("SELECT 1 FROM friend_requests WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'", [user.id, row.id])),
        incomingRequest: Boolean(get("SELECT 1 FROM friend_requests WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'", [row.id, user.id]))
      }));
      return sendJson(res, 200, { users });
    }

    const profileMatch = url.pathname.match(/^\/api\/users\/([^/]+)$/);
    if (req.method === "GET" && profileMatch) {
      const profileRow = getUserByUsername(decodeURIComponent(profileMatch[1]));
      if (!profileRow || profileRow.status !== "active") return sendError(res, 404, "User not found.");
      const posts = all(
        `SELECT p.id AS postId, p.content, p.created_at AS createdAt, ${profileSelect("u", "p2")}
         FROM posts p JOIN users u ON u.id = p.user_id JOIN profiles p2 ON p2.user_id = u.id
         WHERE p.user_id = ? ORDER BY p.created_at DESC`,
        [profileRow.id]
      ).map((post) => decoratePost(post, user.id));
      const friends = all(
        `SELECT ${profileSelect()} FROM friendships f JOIN users u ON u.id = f.friend_id JOIN profiles p ON p.user_id = u.id WHERE f.user_id = ?`,
        [profileRow.id]
      ).map(rowToPublicUser);
      return sendJson(res, 200, {
        user: rowToPublicUser(profileRow),
        posts,
        friends,
        isFriend: areFriends(user.id, profileRow.id),
        isMe: user.id === profileRow.id
      });
    }

    if (route === "PUT /api/profile") {
      const body = await readBody(req);
      run(
        `UPDATE profiles SET full_name = ?, email = ?, address = ?, occupation = ?, course = ?, bio = ?, updated_at = ? WHERE user_id = ?`,
        [
          String(body.fullName || user.fullName).trim(),
          String(body.email || "").trim(),
          String(body.address || "").trim(),
          String(body.occupation || "").trim(),
          String(body.course || "").trim(),
          String(body.bio || "").trim(),
          nowIso(),
          user.id
        ]
      );
      return sendJson(res, 200, { user: rowToPublicUser(getUserById(user.id)) });
    }

    if (route === "GET /api/friends") {
      const friends = all(
        `SELECT ${profileSelect()} FROM friendships f JOIN users u ON u.id = f.friend_id JOIN profiles p ON p.user_id = u.id WHERE f.user_id = ? ORDER BY p.full_name`,
        [user.id]
      ).map(rowToPublicUser);
      const requests = all(
        `SELECT fr.id, fr.created_at AS createdAt, ${profileSelect()}
         FROM friend_requests fr JOIN users u ON u.id = fr.from_user_id JOIN profiles p ON p.user_id = u.id
         WHERE fr.to_user_id = ? AND fr.status = 'pending' ORDER BY fr.created_at DESC`,
        [user.id]
      ).map((row) => ({ id: row.id, createdAt: row.createdAt, fromUser: rowToPublicUser(row) }));
      return sendJson(res, 200, { friends, requests });
    }

    if (route === "POST /api/friend-requests") {
      const body = await readBody(req);
      const target = getUserByUsername(String(body.to || "").trim());
      if (!target || target.status !== "active") return sendError(res, 404, "User not found.");
      if (target.id === user.id) return sendError(res, 400, "You cannot add yourself.");
      if (areFriends(user.id, target.id)) return sendError(res, 409, "You are already friends.");
      if (!get("SELECT 1 FROM friend_requests WHERE from_user_id = ? AND to_user_id = ? AND status = 'pending'", [user.id, target.id])) {
        run("INSERT INTO friend_requests (id, from_user_id, to_user_id, status, created_at) VALUES (?, ?, ?, 'pending', ?)", [
          crypto.randomUUID(),
          user.id,
          target.id,
          nowIso()
        ]);
        createNotification(target.id, user.id, "friend", `${user.fullName} sent you a friend request.`);
      }
      return sendJson(res, 201, { ok: true });
    }

    const requestActionMatch = url.pathname.match(/^\/api\/friend-requests\/([^/]+)\/(accept|decline)$/);
    if (req.method === "POST" && requestActionMatch) {
      const request = get("SELECT * FROM friend_requests WHERE id = ? AND to_user_id = ? AND status = 'pending'", [requestActionMatch[1], user.id]);
      if (!request) return sendError(res, 404, "Friend request not found.");
      if (requestActionMatch[2] === "accept") {
        addFriendship(request.from_user_id, request.to_user_id);
        createNotification(request.from_user_id, user.id, "friend", `${user.fullName} accepted your friend request.`);
      }
      run("UPDATE friend_requests SET status = ? WHERE id = ?", [requestActionMatch[2] === "accept" ? "accepted" : "declined", request.id]);
      return sendJson(res, 200, { ok: true });
    }

    const unfriendMatch = url.pathname.match(/^\/api\/friends\/([^/]+)$/);
    if (req.method === "DELETE" && unfriendMatch) {
      const target = getUserByUsername(decodeURIComponent(unfriendMatch[1]));
      if (target) removeFriendship(user.id, target.id);
      return sendJson(res, 200, { ok: true });
    }

    if (route === "GET /api/messages") {
      const rows = all(
        `SELECT m.id, m.body, m.created_at AS createdAt, fu.username AS fromUsername, tu.username AS toUsername,
          CASE WHEN m.from_user_id = ? THEN m.to_user_id ELSE m.from_user_id END AS otherId
         FROM messages m JOIN users fu ON fu.id = m.from_user_id JOIN users tu ON tu.id = m.to_user_id
         WHERE m.from_user_id = ? OR m.to_user_id = ? ORDER BY m.created_at ASC`,
        [user.id, user.id, user.id]
      );
      const grouped = new Map();
      for (const message of rows) {
        if (!grouped.has(message.otherId)) grouped.set(message.otherId, []);
        grouped.get(message.otherId).push({ id: message.id, from: message.fromUsername, to: message.toUsername, body: message.body, createdAt: message.createdAt });
      }
      const conversations = Array.from(grouped.entries()).map(([otherId, messages]) => ({
        user: rowToPublicUser(getUserById(otherId)),
        messages,
        lastMessage: messages[messages.length - 1]
      })).sort((a, b) => new Date(b.lastMessage.createdAt) - new Date(a.lastMessage.createdAt));
      return sendJson(res, 200, { conversations });
    }

    const messageMatch = url.pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (req.method === "GET" && messageMatch) {
      const other = getUserByUsername(decodeURIComponent(messageMatch[1]));
      if (!other) return sendError(res, 404, "User not found.");
      const messages = all(
        `SELECT m.id, m.body, m.created_at AS createdAt, fu.username AS fromUsername, tu.username AS toUsername
         FROM messages m JOIN users fu ON fu.id = m.from_user_id JOIN users tu ON tu.id = m.to_user_id
         WHERE (m.from_user_id = ? AND m.to_user_id = ?) OR (m.from_user_id = ? AND m.to_user_id = ?)
         ORDER BY m.created_at ASC`,
        [user.id, other.id, other.id, user.id]
      ).map((message) => ({ id: message.id, from: message.fromUsername, to: message.toUsername, body: message.body, createdAt: message.createdAt }));
      return sendJson(res, 200, { messages });
    }

    if (req.method === "POST" && messageMatch) {
      const target = getUserByUsername(decodeURIComponent(messageMatch[1]));
      if (!target || target.status !== "active") return sendError(res, 404, "User not found.");
      const body = await readBody(req);
      const text = String(body.body || "").trim();
      if (!text) return sendError(res, 400, "Message cannot be empty.");
      const id = crypto.randomUUID();
      run("INSERT INTO messages (id, from_user_id, to_user_id, body, created_at) VALUES (?, ?, ?, ?, ?)", [id, user.id, target.id, text, nowIso()]);
      createNotification(target.id, user.id, "message", `${user.fullName} sent you a message.`);
      return sendJson(res, 201, { message: { id, from: user.username, to: target.username, body: text, createdAt: nowIso() } });
    }

    if (route === "GET /api/notifications") {
      const notifications = all(
        `SELECT n.id, n.type, n.text, n.read_at AS readAt, n.created_at AS createdAt, u.username AS fromUsername
         FROM notifications n LEFT JOIN users u ON u.id = n.from_user_id
         WHERE n.to_user_id = ? ORDER BY n.created_at DESC`,
        [user.id]
      ).map((item) => ({ ...item, read: Boolean(item.readAt), from: item.fromUsername }));
      return sendJson(res, 200, { notifications });
    }

    if (route === "POST /api/notifications/read") {
      run("UPDATE notifications SET read_at = ? WHERE to_user_id = ? AND read_at IS NULL", [nowIso(), user.id]);
      return sendJson(res, 200, { ok: true });
    }

    sendError(res, 404, "API route not found.");
  } catch (error) {
    sendError(res, 400, error.message || "Something went wrong.");
  }
}

createSchema();
migrateInitialData();

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res);
  } else {
    serveStatic(req, res);
  }
});

server.listen(PORT, () => {
  console.log(`Roma Social is running at http://localhost:${PORT}`);
});
