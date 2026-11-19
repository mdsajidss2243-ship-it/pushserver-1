/**
 * Wevlo Push Server
 * - Android অ্যাপের FCM token রেজিস্টার করে (Firestore এ সেভ হয়, তাই Render restart এ হারায় না)
 * - DATA-ONLY মেসেজ পাঠায়: data: { title, body, imageUrl? }
 *
 * Endpoints:
 *   GET  /                      health check
 *   POST /register-app          { appId, password? }                       (ADMIN)
 *   POST /register-token        { token, appId, userAgent?, password? }    (অ্যাপ থেকে)
 *   POST /send-all              { appId, title, body, imageUrl? }          (ADMIN)
 *   POST /send                  { token, title, body, imageUrl? }          (ADMIN)
 *   GET  /stats/:appId          টোকেন সংখ্যা                                 (ADMIN)
 *
 * ADMIN = header  x-admin-key: <ADMIN_KEY env>   (ADMIN_KEY সেট না থাকলে খোলা থাকবে)
 */
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

// ───────── Firebase Admin init ─────────
function loadServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  }
  const p = path.join(__dirname, "serviceAccountKey.json");
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

admin.initializeApp({ credential: admin.credential.cert(loadServiceAccount()) });
const db = admin.firestore();
const messaging = admin.messaging();

const APPS = db.collection("push_apps");
const TOKENS = db.collection("push_tokens");

// ───────── Helpers ─────────
const ADMIN_KEY = process.env.ADMIN_KEY || "";
if (!ADMIN_KEY) console.warn("⚠️  ADMIN_KEY সেট করা নেই — send endpoint গুলো সবার জন্য খোলা!");

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 32).toString("hex");
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(String(password || ""), salt, 32).toString("hex");
  return safeEqual(test, hash);
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return next();
  if (safeEqual(req.get("x-admin-key") || "", ADMIN_KEY)) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: e.message || "Server error" });
  });

function buildData({ title, body, imageUrl }) {
  const data = { title: String(title || "Wevlo"), body: String(body || "") };
  if (imageUrl) data.imageUrl = String(imageUrl);
  return data; // FCM data এর সব value অবশ্যই string
}

const DEAD_TOKEN_CODES = new Set([
  "messaging/registration-token-not-registered",
  "messaging/invalid-registration-token",
]);

// ───────── App ─────────
const app = express();
app.use(cors());
app.use(express.json({ limit: "100kb" }));

app.get("/", (req, res) => res.json({ ok: true, service: "wevlo-push-server" }));

// অ্যাপ রেজিস্টার (পাসওয়ার্ড ঐচ্ছিক)
app.post("/register-app", requireAdmin, wrap(async (req, res) => {
  const { appId, password } = req.body || {};
  if (!appId) return res.status(400).json({ error: "appId দরকার" });

  const doc = { createdAt: admin.firestore.FieldValue.serverTimestamp() };
  if (password) doc.passwordHash = hashPassword(String(password));
  await APPS.doc(appId).set(doc, { merge: true });

  res.json({ ok: true, appId, protected: !!password });
}));

// অ্যাপ থেকে token রেজিস্টার
app.post("/register-token", wrap(async (req, res) => {
  const { token, appId, userAgent, password } = req.body || {};
  if (!token || !appId) return res.status(400).json({ error: "token ও appId দরকার" });

  const appRef = APPS.doc(appId);
  const appSnap = await appRef.get();

  if (!appSnap.exists) {
    // প্রথমবার — পাসওয়ার্ডবিহীন অ্যাপ হিসেবে অটো-তৈরি
    await appRef.set({ createdAt: admin.firestore.FieldValue.serverTimestamp() });
  } else {
    const hash = appSnap.data().passwordHash;
    if (hash && !checkPassword(password, hash)) {
      return res.status(403).json({ error: "ভুল পাসওয়ার্ড" });
    }
  }

  await TOKENS.doc(sha(token)).set(
    {
      token: String(token),
      appId: String(appId),
      userAgent: String(userAgent || ""),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  res.json({ ok: true });
}));

// অ্যাপের সব ডিভাইসে পাঠান
app.post("/send-all", requireAdmin, wrap(async (req, res) => {
  const { appId, title, body, imageUrl } = req.body || {};
  if (!appId) return res.status(400).json({ error: "appId দরকার" });
  if (!title && !body) return res.status(400).json({ error: "title বা body দরকার" });

  const snap = await TOKENS.where("appId", "==", appId).get();
  const entries = snap.docs.map((d) => ({ id: d.id, token: d.data().token }));
  if (entries.length === 0) return res.json({ ok: true, sent: 0, failed: 0, removed: 0 });

  const data = buildData({ title, body, imageUrl });
  let sent = 0, failed = 0;
  const dead = [];

  for (let i = 0; i < entries.length; i += 500) {
    const chunk = entries.slice(i, i + 500);
    const result = await messaging.sendEachForMulticast({
      tokens: chunk.map((e) => e.token),
      data,
      android: { priority: "high" },
    });
    sent += result.successCount;
    failed += result.failureCount;
    result.responses.forEach((r, idx) => {
      if (!r.success && DEAD_TOKEN_CODES.has(r.error && r.error.code)) dead.push(chunk[idx].id);
    });
  }

  // মৃত token মুছে ফেলা
  for (let i = 0; i < dead.length; i += 400) {
    const batch = db.batch();
    dead.slice(i, i + 400).forEach((id) => batch.delete(TOKENS.doc(id)));
    await batch.commit();
  }

  res.json({ ok: true, total: entries.length, sent, failed, removed: dead.length });
}));

// একটি নির্দিষ্ট token এ পাঠান
app.post("/send", requireAdmin, wrap(async (req, res) => {
  const { token, title, body, imageUrl } = req.body || {};
  if (!token) return res.status(400).json({ error: "token দরকার" });

  try {
    const id = await messaging.send({
      token,
      data: buildData({ title, body, imageUrl }),
      android: { priority: "high" },
    });
    res.json({ ok: true, messageId: id });
  } catch (e) {
    if (DEAD_TOKEN_CODES.has(e.code)) await TOKENS.doc(sha(token)).delete().catch(() => {});
    res.status(400).json({ error: e.message, code: e.code });
  }
}));

// কতগুলো ডিভাইস রেজিস্টার আছে
app.get("/stats/:appId", requireAdmin, wrap(async (req, res) => {
  const snap = await TOKENS.where("appId", "==", req.params.appId).count().get();
  res.json({ appId: req.params.appId, tokens: snap.data().count });
}));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Push server running on :${PORT}`));
