// index.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // ✅ defines 'upload' used later in /api/upload-avatar

const path = require('path');
const fs = require('fs');
const shortid = require('shortid');
const http = require('http');
const { OAuth2Client } = require('google-auth-library');
const sgMail = require('@sendgrid/mail');
const cloudinary = require('cloudinary').v2;
const { Server } = require("socket.io");

// ✅ fetch support for CommonJS (ESM-safe wrapper)
const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));
/// ===== Config (must be above any signing/verifying) =====
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'rom_seed_dev_change_me';
const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN || '30d';

// ===== JWT Sign Helper =====
const signToken = (user) => jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: TOKEN_EXPIRES_IN });



// =======================
// 📦 DATABASE (LowDB)
// =======================
const db = new Low(new JSONFile('db.json'));

(async () => {
  await db.read();
  db.data ||= {
    users: [],
    posts: [],
    likes: [],
    matches: [],
    notifications: [],
    messages: [],
    blocks: [],
    reports: [],
    roomMessages: [],
    matchStreaks: {},
  };
  await db.write();
})();

/* -------------------------------------------
   🛡️ Global write guard for Windows EPERM
   - Serializes writes
   - Retries EPERM/EBUSY with backoff
-------------------------------------------- */
const _rawWrite = db.write.bind(db);
let _writeQueue = Promise.resolve();

async function writeWithRetry() {
  // chain to ensure single writer
  _writeQueue = _writeQueue.then(async () => {
    const MAX_TRIES = 6;               // ~ cumulative ~1s backoff
    let attempt = 0;
    while (true) {
      try {
        await _rawWrite();
        return;
      } catch (err) {
        const code = err && err.code;
        if (code === 'EPERM' || code === 'EBUSY') {
          attempt++;
          if (attempt >= MAX_TRIES) throw err;
          // exponential-ish backoff: 50, 100, 150, 200, 250, 300ms
          const delay = 50 * attempt;
          await new Promise(r => setTimeout(r, delay));
          continue;
        }
        // other errors: rethrow
        throw err;
      }
    }
  });
  return _writeQueue;
}

// Monkey-patch LowDB's write everywhere
db.write = writeWithRetry;



// ===== Cloudinary =====
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ===== Feature toggles =====
const ENABLE_BLURRED_PROFILES = String(process.env.ENABLE_BLURRED_PROFILES || 'true') === 'true';
const ENABLE_LIKES_MATCHES   = String(process.env.ENABLE_LIKES_MATCHES || 'true') === 'true';
const ENABLE_REALTIME_CHAT   = String(process.env.ENABLE_REALTIME_CHAT || 'true') === 'true';
const ENABLE_AI_WINGMAN      = String(process.env.ENABLE_AI_WINGMAN || 'false') === 'true';

// Optional admin for moderation list
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
// ===== Premium / Safety flags (server-side gating) =====
const SHOW_PRIVATE    = String(process.env.SHOW_PRIVATE    || 'true')  === 'true';  // filter-only
const SHOW_RESTRICTED = String(process.env.SHOW_RESTRICTED || 'false') === 'true'; // EXPLICIT, premium + KYC + consent

// Vibe bands
const PUBLIC_VIBES     = new Set(["serious","casual","friends","gymbuddy"]);
const PRIVATE_VIBES    = new Set(["flirty","chill","timepass"]);
const RESTRICTED_VIBES = new Set(["ons","threesome","onlyfans"]);

function isAllowedVibeKey(v) {
  v = String(v || '').toLowerCase();
  return (
    PUBLIC_VIBES.has(v) ||
    (SHOW_PRIVATE && PRIVATE_VIBES.has(v)) ||
    (SHOW_RESTRICTED && RESTRICTED_VIBES.has(v))
  );
}
function isRestricted(v) {
  return RESTRICTED_VIBES.has(String(v || '').toLowerCase());
}
function hasPremium(u) {
  return u && (u.premiumTier === "plus" || u.premiumTier === "pro");
}
function isAgeVerified(u) {
  return u && u.kycStatus === "verified";
}
function canUseRestricted(u) {
  return SHOW_RESTRICTED && hasPremium(u) && isAgeVerified(u) && u?.consent?.restrictedAccepted;
}

// ===== SendGrid =====
sgMail.setApiKey(process.env.SENDGRID_API_KEY || '');

// =======================
// 🔧 MISSING HELPER FUNCTIONS
// =======================

// Base user sanitization (✅ updated to include profileComplete flag)
function baseSanitizeUser(user) {
  if (!user) return null;

  // Remove sensitive fields but keep important flags
  const { passwordHash, emailVerificationCode, pendingEmailChange, ...safe } = user;

  // ✅ Ensure frontend knows if profile setup is done
  return {
    ...safe,
    profileComplete: user.profileComplete,
  };
}


// Block check helper
function isBlocked(user1, user2) {
  if (!db.data.blocks) return false;
  return db.data.blocks.some(
    b => 
      (b.blocker === user1 && b.blocked === user2) ||
      (b.blocker === user2 && b.blocked === user1)
  );
}

// Date helpers for name change cooldown
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
function msToDays(ms) {
  return Math.ceil(ms / (24 * 60 * 60 * 1000));
}

// Distance calculator (for wingman tips)
function distanceKm(loc1, loc2) {
  const R = 6371;
  const dLat = (loc2.lat - loc1.lat) * Math.PI / 180;
  const dLon = (loc2.lng - loc1.lng) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(loc1.lat * Math.PI / 180) * Math.cos(loc2.lat * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}
// Helper to get/create a room record for chat rooms
async function getRoomDoc(roomId) {
  await db.read();
  if (!db.data.roomMessages) db.data.roomMessages = [];
  let doc = db.data.roomMessages.find((r) => r.roomId === roomId);
  if (!doc) {
    doc = { roomId, list: [] };
    db.data.roomMessages.push(doc);
    await db.write();
  }
  return doc;
}
// Pure in-memory increment (no db.read/db.write here)
// Directed (from -> to) streak increment
function incMatchStreakOut(dbData, fromId, toId) {
  dbData.matchStreaks = dbData.matchStreaks || {};
  const k = `${String(fromId)}_${String(toId)}`; // 🔁 NO SORT — directed

  let s = dbData.matchStreaks[k];
  if (!s) {
    s = dbData.matchStreaks[k] = {
      from: String(fromId),
      to: String(toId),
      count: 0,
      lastBuzz: null,
      createdAt: Date.now(),
    };
  }

  s.count = Number(s.count || 0) + 1;  // only the sender’s counter goes up
  s.lastBuzz = Date.now();
  return s; // caller will db.write() once
}


// ===== Config =====

const OBFUSCATION_MIN_METERS = Number(process.env.OBFUSCATION_MIN_METERS || 50);
const OBFUSCATION_MAX_METERS = Number(process.env.OBFUSCATION_MAX_METERS || 200);

// Google OAuth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '579443399527-3q3lpblalkiqces1d0etdgjfj301b75l.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ===== App / Server / Socket =====
const app = express();
const server = http.createServer(app);
// Simple in-process lock to serialize buzz per pair
const buzzLocks = new Set();

// =======================
// 🛡️ CORS CONFIG (clean, unified)
// =======================

const allowedOrigins = [
  "https://rombuzz.com",
  "https://www.rombuzz.com",
  "https://rombuzz.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS not allowed for this origin: " + origin));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
// ✅ Handle all preflight OPTIONS requests safely (Express 5+ compatible)
app.options(/.*/, cors());




// Basic middleware setup
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(
  helmet({
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

async function createNotification({ fromId, toId, type, message }) {
  // Delegate to the global helper so there’s only one code path.
  await sendNotification(toId, {
    fromId,
    type,
    message,
  });
}


// =======================
// 🔔 SOCKET.IO SETUP
// =======================
const io = new Server(server, {
  cors: {
    origin: [
      "https://rombuzz.com",
      "https://www.rombuzz.com",
      "https://rombuzz.vercel.app",
      "http://localhost:3000",
      "http://localhost:5173",
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
  },
});

let onlineUsers = {};

// ✅ Top-level notification helper (NOT inside io.on)
global.sendNotification = async (toId, payload) => {
  try {
    await db.read();
    
    // Ensure notifications array exists
    if (!db.data.notifications) {
      db.data.notifications = [];
    }
    
   const newNotif = {
  id: shortid.generate(),
  toId,
  fromId: payload.fromId || null,
  type: payload.type || "system",
  message: payload.message || "You have a new notification!",
  createdAt: new Date().toISOString(),
  read: false,

  // 🆕 optional deep-link data (frontend will use if present)
  href: payload.href || null,
  // optional entity context
  entity: payload.entity || null,            // e.g. "post"
  entityId: payload.entityId || null,        // e.g. postId
  postId: payload.postId || null,            // alias
  postOwnerId: payload.postOwnerId || null,  // owner of that post
};

    
    db.data.notifications.push(newNotif);
    await db.write();

  // 👉 De-dupe emit: only to the private room
io.to(String(toId)).emit("notification", newNotif);
if (onlineUsers[toId]) {
  console.log("📨 Notification sent to room of:", toId);
} else {
  console.log("📨 Notification saved, user currently offline (room emit queued):", toId);
}


    
  } catch (error) {
    console.error("❌ sendNotification error:", error);
    // Don't throw - just log the error
  }
};
// =======================
// Single connection handler
// =======================
io.on("connection", (socket) => {
  console.log(`⚡️ New client connected: ${socket.id}`);
  let currentUserId = null;

      socket.on("match", (data) => {
    const { otherUserId, type } = data || {};
    if (onlineUsers[otherUserId]) {
      io.to(String(otherUserId)).emit("match", {
        fromId: socket.userId,
        type,
      });
      // 💫 When both should open each other's profile
// ✅ Correct: relay match-open to both users
socket.on("buzz_match_open_profile", (data) => {
  const { otherUserId, selfieUrl } = data || {};
  console.log("💫 buzz_match_open_profile:", data);

  // Find both sockets
  const myId = currentUserId;
  const peerId = otherUserId;

  if (!myId || !peerId) return;

  // Emit to both users' private rooms
  if (onlineUsers[myId]) {
    io.to(String(myId)).emit("buzz_match_open_profile", {
      otherUserId: peerId,
      selfieUrl,
    });
  }
  if (onlineUsers[peerId]) {
    io.to(String(peerId)).emit("buzz_match_open_profile", {
      otherUserId: myId,
      selfieUrl,
    });
  }

  console.log(`💫 buzz_match_open_profile relayed between ${myId} ↔ ${peerId}`);
});


      console.log(`💥 Match emitted between ${socket.userId} ↔ ${otherUserId}`);
    }
  });

  // Allow explicit register from client
// inside io.on("connection")
// ✅ Support both legacy and new event names
socket.on("user:register", (userId) => {
  if (!userId) return;
  onlineUsers[userId] = socket.id;
  currentUserId = userId;
  socket.join(String(userId));
  io.emit("presence:online", { userId });
  console.log(`🔌 (user:register) ${userId} → ${socket.id} (joined private room)`);
});

socket.on("register", (userId) => {
  if (!userId) return;
  onlineUsers[userId] = socket.id;
  currentUserId = userId;
  socket.join(String(userId));
  io.emit("presence:online", { userId });
  console.log(`🔌 (legacy register) ${userId} → ${socket.id}`);
});



  // Respect feature toggle
  if (!ENABLE_REALTIME_CHAT) {
    socket.emit("info", { message: "Realtime chat disabled by config" });
    return;
  }

  // Optional JWT in handshake
  const token = socket.handshake?.auth?.token;
  if (token) {
    try {
      const data = jwt.verify(token, JWT_SECRET);
      const userId = data.id;
      onlineUsers[userId] = socket.id;
      currentUserId = userId;

      (async () => {
        await db.read();
        const u = db.data.users.find((x) => x.id === userId);
        if (u) {
          u.lastOnline = Date.now();
          await db.write();
        }
      })();

      socket.join(userId); // personal room
      socket.emit("connected", { userId });
      console.log(`✅ Authenticated user ${userId} joined their private room.`);
    } catch {
      socket.emit("error", { message: "Invalid auth token" });
    }
  }

  // -------- Rooms --------
  socket.on("joinRoom", (roomId) => {
    if (!roomId) return;
    socket.join(roomId);
    console.log(`🟢 ${socket.id} joined room ${roomId}`);
  });

  socket.on("leaveRoom", (roomId) => {
    if (!roomId) return;
    socket.leave(roomId);
    console.log(`🔴 ${socket.id} left room ${roomId}`);
  });

  // -------- UX signals --------
  socket.on("typing", ({ roomId, fromId }) => {
    if (!roomId || !fromId) return;
    socket.to(roomId).emit("typing", { fromId });
  });

  socket.on("message:seen", ({ roomId, msgId }) => {
    if (!roomId || !msgId) return;
    socket.to(roomId).emit("message:seen", msgId);
  });
  // 🧨 Auto-delete view-once messages when seen
socket.on("message:seen", async ({ roomId, msgId }) => {
  await db.read();
  const msg = db.data.messages?.find(m => m.id === msgId);
  if (msg && msg.ephemeral?.mode === "once") {
    // Remove from DB and notify peers
    db.data.messages = db.data.messages.filter(m => m.id !== msgId);
    await db.write();
    io.to(roomId).emit("message:removed", { id: msgId });
  }
});
// Auto-remove messages that expired (e.g., 24h snaps)
setInterval(async () => {
  await db.read();
  const now = Date.now();
  db.data.messages = db.data.messages.filter(m => {
    if (!m.expireAt) return true;
    return new Date(m.expireAt).getTime() > now;
  });
  await db.write();
}, 60 * 60 * 1000); // hourly cleanup



  // -------- Plain realtime dispatch (persist if needed) --------
  socket.on("sendMessage", async (msg) => {
    try {
      if (!msg || !msg.roomId) return;
      const { roomId, from, to, text } = msg;

      // Block check
      if (isBlocked(from, to)) {
        socket.emit("warn", {
          roomId,
          reason: "blocked",
          message: "This user is unavailable to chat.",
        });
        return;
      }

      // Persist if not already saved by REST
      const doc = await getRoomDoc(roomId); // assumes your helper exists
      if (!doc.list.find((m) => m.id === msg.id)) {
        doc.list.push({
          id: msg.id || shortid.generate(),
          roomId,
          from,
          to,
          text: text || "",
          type: msg.type || (String(text || "").startsWith("::RBZ::") ? "media" : "text"),
          time: msg.time || new Date().toISOString(),
          edited: false,
          deleted: false,
          reactions: {},
          hiddenFor: [],
        });
        await db.write();
      }

// ✅ Emit to both participants for real-time sync
io.to(roomId).emit("chat:message", {
  id: msg.id,
  roomId,
  from,
  to,
  text: msg.text || text || "",
  time: msg.time,
  type: msg.type || "text",
});

// ✅ Also ping recipient’s private room (for notification badge)
io.to(String(to)).emit("chat:message", {
  id: msg.id,
  roomId,
  from,
  to,
  text: msg.text || text || "",
  time: msg.time,
  type: msg.type || "text",
});

// ✅ Belt-and-suspenders: if recipient socket ID exists, hit directly
const sid = onlineUsers[to];
if (sid) {
  io.to(sid).emit("chat:message", {
    id: msg.id,
    roomId,
    from,
    to,
    text: msg.text || text || "",
    time: msg.time,
    type: msg.type || "text",
  });
}



console.log(`💬 Message in ${roomId} from ${from} → ${to}`);

  } catch (e) {
    console.error("sendMessage error:", e);
  }
});

// =======================================================
// 📞 REAL-TIME VIDEO & VOICE CALL SIGNALING (FIXED)
// =======================================================

// Caller → Callee - FIXED
socket.on("call:offer", (data) => {
  const { roomId, type, from } = data;
  if (!roomId || !type || !from) {
    console.log("❌ Missing roomId, type, or from in call:offer");
    return;
  }
  
  // Extract peer ID from roomId (roomId is "user1_user2")
  const [user1, user2] = roomId.split('_');
  const peerId = user1 === from ? user2 : user1;
  
  const sid = onlineUsers[peerId];
  if (sid) {
    io.to(sid).emit("call:offer", { roomId, type, from });
    console.log(`📞 Offer (${type}) ${from} → ${peerId}`);
  } else {
    console.log(`❌ Peer ${peerId} not online for call offer from ${from}`);
  }
});

// Callee → Caller - FIXED
socket.on("call:answer", (data) => {
  const { roomId, accepted, from } = data;
  if (!roomId || !from) return;
  
  const [user1, user2] = roomId.split('_');
  const peerId = user1 === from ? user2 : user1;
  
  const sid = onlineUsers[peerId];
  if (sid) {
    io.to(sid).emit("call:answer", { roomId, accepted, from });
    console.log(`📞 Answer ${accepted ? 'accepted' : 'declined'} ${from} → ${peerId}`);
  }
});

// ICE candidate exchange - FIXED
socket.on("call:signal", (data) => {
  const { roomId, payload } = data;
  if (!roomId || !payload) return;
  
  const { from, data: signalData } = payload;
  const [user1, user2] = roomId.split('_');
  const peerId = user1 === from ? user2 : user1;
  
  const sid = onlineUsers[peerId];
  if (sid) {
    io.to(sid).emit("call:signal", { roomId, payload: { from, data: signalData } });
    console.log(`📡 ICE signal ${from} → ${peerId}`);
  }
});

// End call - FIXED
socket.on("call:end", (data) => {
  const { roomId, reason, from } = data;
  if (!roomId || !from) return;
  
  const [user1, user2] = roomId.split('_');
  const peerId = user1 === from ? user2 : user1;
  
  const sid = onlineUsers[peerId];
  if (sid) {
    io.to(sid).emit("call:end", { roomId, reason, from });
    console.log(`📞 Call ended ${from} → ${peerId}: ${reason}`);
  }
});

// --- Meet Request (notify the other user to show the popup) ---
socket.on("meet:request", async ({ from, to }) => {
  try {
    if (!from || !to) return;
    await db.read();
    const fromUser = db.data.users.find(u => String(u.id) === String(from)) || { id: from };
    const sid = onlineUsers[to];
    if (sid) {
      io.to(sid).emit("meet:request", { from: fromUser });
      console.log(`📨 meet:request ${from} → ${to}`);
    }
  } catch (e) {
    console.error("meet:request error", e);
  }
});

// --- Meet Accept (store my coords; if both have coords → suggest) ---
socket.on("meet:accept", async ({ to, from, coords }) => {
  try {
    console.log("📍 meet:accept from", from, "→", to, coords);
    if (!from || !to) return;
    if (!coords || typeof coords.lat !== "number" || typeof coords.lng !== "number") return;

    await db.read();
    const me  = db.data.users.find(u => String(u.id) === String(from));
    const you = db.data.users.find(u => String(u.id) === String(to));
    if (!me || !you) return;

    // Save my latest location
    me.location = { lat: Number(coords.lat), lng: Number(coords.lng) };
    await db.write();

    // If the peer doesn't have a location yet, ping them with my coords
    if (!you.location?.lat || !you.location?.lng) {
      const sid = onlineUsers[to];
      if (sid) io.to(sid).emit("meet:accept", { from, coords: me.location });
      return;
    }

    // Both have locations → compute midpoint + fetch real places
    const res = await fetch("http://localhost:4000/api/meet/suggest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: me.location, b: you.location }),
    });
    const data = await res.json().catch(() => ({}));
    const places = Array.isArray(data.places) ? data.places : [];

    const payload = {
      from: { id: me.id, firstName: me.firstName, lastName: me.lastName },
      midpoint: data.midpoint || {
        lat: (me.location.lat + you.location.lat) / 2,
        lng: (me.location.lng + you.location.lng) / 2,
      },
      places,
    };

    // send to both users
    const sidMe  = onlineUsers[me.id];
    const sidYou = onlineUsers[you.id];
    if (sidMe)  io.to(sidMe).emit("meet:suggest", payload);
    if (sidYou) io.to(sidYou).emit("meet:suggest", payload);
    console.log(`📍 meet:suggest → ${me.id}, ${you.id} (${places.length} places)`);
  } catch (e) {
    console.error("meet:accept error", e);
  }
});

// =======================
// 📍 MEET SUGGESTIONS (OpenStreetMap Overpass + fallback)
// =======================
app.post("/api/meet/suggest", async (req, res) => {
  try {
    const { a, b } = req.body || {};
    if (!a || !b) return res.status(400).json({ error: "a & b required" });

    const mid = {
      lat: (Number(a.lat) + Number(b.lat)) / 2,
      lng: (Number(a.lng) + Number(b.lng)) / 2,
    };

    const radius = 1500;
    const overpassURL = `https://overpass-api.de/api/interpreter?data=[out:json][timeout:25];(
      node["amenity"="cafe"](around:${radius},${mid.lat},${mid.lng});
      node["amenity"="restaurant"](around:${radius},${mid.lat},${mid.lng});
      node["leisure"="park"](around:${radius},${mid.lat},${mid.lng});
      node["amenity"="cinema"](around:${radius},${mid.lat},${mid.lng});
    );out center;`;

    let places = [];
    try {
      const r = await fetch(overpassURL, { timeout: 15000 });
      const j = await r.json();
      if (Array.isArray(j.elements)) {
        places = j.elements.slice(0, 15).map((p) => ({
          id: p.id,
          name:
            p.tags?.name ||
            p.tags?.brand ||
            `${p.tags?.amenity || p.tags?.leisure || "Place"} #${p.id}`,
          category: p.tags?.amenity || p.tags?.leisure || "venue",
          coords: { lat: p.lat, lng: p.lon },
          address:
            p.tags?.addr_full ||
            [p.tags?.addr_street, p.tags?.addr_city].filter(Boolean).join(", ") ||
            "Unknown",
        }));
      }
    } catch (err) {
      console.warn("⚠️ Overpass slow/unreachable; using fallback", err.message || err);
    }

    if (!places.length) {
      places = [
        {
          id: "midpoint-fallback",
          name: "Center Point Café",
          category: "cafe",
          coords: mid,
          address: "Midpoint",
        },
      ];
    }

    res.json({ midpoint: mid, places });
  } catch (err) {
    console.error("❌ meet/suggest error:", err);
    res.status(500).json({ error: "Failed to fetch places" });
  }
});


/* ======================
   EMAIL VERIFICATION
====================== */
let verificationCodes = {}; // { emailLower: { code, expires } }

app.post('/api/auth/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000; // 10 minutes
  verificationCodes[email.toLowerCase()] = { code, expires };

  try {
    if (!process.env.SENDGRID_API_KEY) {
      // Dev fallback: log code
      console.log(`📧 [DEV] Verification code for ${email}: ${code}`);
      return res.json({ success: true, dev: true });
    }
    const msg = {
      to: email,
      from: process.env.FROM_EMAIL || 'myprojectthisyear2025@gmail.com',
      subject: 'Your Rombuzz Verification Code',
      text: `Your verification code is ${code}. It will expire in 10 minutes.`,
      html: `<p>Your verification code is <strong>${code}</strong>. It will expire in 10 minutes.</p>`,
    };
    await sgMail.send(msg);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send code' });
  }
});

// =======================
// 📧 EMAIL / PASSWORD LOGIN
// =======================
app.post("/api/auth/login", async (req, res) => {
  console.log("🟢 Login API hit with body:", req.body);

  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email & password required" });

  await db.read();
  const emailLower = String(email || "").trim().toLowerCase();
const user = db.data.users.find((u) => (u.email || "").toLowerCase() === emailLower);

  if (!user) return res.status(401).json({ error: "Invalid credentials" });
console.log("DEBUG LOGIN →", {
  email,
  passwordProvided: password,
  passwordHashStored: user.passwordHash,
});

  // ✅ Proper bcrypt compare (your hash is stored at signup)
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken({ id: user.id, email: user.email });
  res.json({ token, user: baseSanitizeUser(user) });
});


// =======================
// 🔁 FORGOT / RESET PASSWORD (Persistent Version)
// =======================

// Step 1 — Send reset code
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "Email is required" });

  await db.read();
  const user = db.data.users.find(
    (u) => (u.email || "").toLowerCase() === email.toLowerCase()
  );
  if (!user)
    return res.status(404).json({ error: "No user found with that email" });

  // ✅ Ensure persistent storage exists
  db.data.resetCodes ||= {};

  const emailLower = email.toLowerCase();
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000; // 10 minutes
  db.data.resetCodes[emailLower] = { code, expires };
  await db.write();

  try {
    if (!process.env.SENDGRID_API_KEY) {
      console.log(`📧 [DEV] Password reset code for ${email}: ${code}`);
      return res.json({ success: true, dev: true });
    }

    const msg = {
      to: email,
      from: process.env.FROM_EMAIL || "myprojectthisyear2025@gmail.com",
      subject: "RomBuzz Password Reset Code",
      text: `Your RomBuzz reset code is ${code}. It expires in 10 minutes.`,
      html: `<p>Your RomBuzz reset code is <strong>${code}</strong>. It expires in 10 minutes.</p>`,
    };
    await sgMail.send(msg);
    res.json({ success: true });
  } catch (err) {
    console.error(
      "❌ SendGrid error:",
      err.response?.body || err.message || err
    );
    res.status(500).json({
      error:
        err.response?.body?.errors?.[0]?.message ||
        err.message ||
        "Failed to send reset code",
    });
  }
});

// Step 2 — Verify and reset
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, code, newPassword } = req.body || {};
  if (!email || !code || !newPassword)
    return res
      .status(400)
      .json({ error: "Email, code, and new password required" });

  await db.read();
  db.data.resetCodes ||= {};
  const emailLower = email.toLowerCase();
  const rec = db.data.resetCodes[emailLower];

  if (!rec)
    return res.status(400).json({ error: "No reset request found" });
  if (rec.expires < Date.now())
    return res.status(400).json({ error: "Code expired" });
  if (rec.code !== code)
    return res.status(400).json({ error: "Invalid code" });

  const user = db.data.users.find(
    (u) => (u.email || "").toLowerCase() === emailLower
  );
  if (!user) return res.status(404).json({ error: "User not found" });

  // ✅ Save new password hash
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  delete db.data.resetCodes[emailLower];
  await db.write();

  res.json({ success: true, message: "Password reset successful" });
});



// =======================
// 🔐 GOOGLE LOGIN / SIGNUP (fixed for CompleteProfile)
// =======================
app.post("/api/auth/google", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Google token required" });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();

    await db.read();
    let user = db.data.users.find((u) => u.email === email);
    let isNew = false;

    // ✅ Handle brand-new Google signups
    if (!user) {
      isNew = true;
      user = {
        id: shortid.generate(),
        email,
        firstName: payload.given_name || "",
        lastName: payload.family_name || "",
        avatar: payload.picture || "",
        passwordHash: "",
        createdAt: Date.now(),

        // Flags
        profileComplete: false,
        hasOnboarded: false,

        // Empty placeholders for later completion
        bio: "",
        dob: null,
        gender: "",
        location: null,
        visibility: "active",
        media: [],
        posts: [],
        interests: [],
        hobbies: [],
        favorites: [],
        visibilityMode: "auto",
        fieldVisibility: {
          age: "public",
          height: "public",
          city: "public",
          orientation: "public",
          interests: "public",
          hobbies: "public",
          likes: "public",
          dislikes: "public",
          lookingFor: "public",
          voiceIntro: "public",
          photos: "matches",
        },
      };
      db.data.users.push(user);
      await db.write();
    }

     const jwtToken = signToken({ id: user.id, email: user.email });

 // ✅ Determine correct status for frontend
const isProfileComplete = Boolean(user.profileComplete);

// ✅ Always send incomplete_profile for brand-new users or anyone with profileComplete=false
if (isNew || !isProfileComplete) {
  console.log("🧩 Returning INCOMPLETE_PROFILE for:", user.email);
  return res.json({
    status: "incomplete_profile",
    token: jwtToken,
    user: baseSanitizeUser(user),
  });
}

// ✅ Existing + completed profile → normal login
console.log("🟢 Returning OK for:", user.email);
res.json({
  status: "ok",
  token: jwtToken,
  user: baseSanitizeUser(user),
});

    // Existing + complete profile → normal login
    res.json({
      status: "ok",
      token: jwtToken,
      user: baseSanitizeUser(user),
    });

  } catch (err) {
    console.error("❌ Google login failed:", err);
    res.status(401).json({ error: "Google login failed" });
  }
});

// =======================
// 🧩 COMPLETE PROFILE ROUTE
// =======================
app.post("/api/profile/complete", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    await db.read();
    const user = db.data.users.find((u) => u.id === userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Update profile fields
    const {
      avatar,
      photos,
      hobbies,
      matchPref,
      locationRadius,
      ageRange,
    } = req.body;

 Object.assign(user, {
  avatar,
  photos: photos || [],
  hobbies,
  matchPref,
  locationRadius,
  ageRange,
  profileComplete: true,
  hasOnboarded: true,
  updatedAt: Date.now(),
});

// ✅ Auto-create MyBuzz & LetsBuzz posts for uploaded photos
if (!db.data.posts) db.data.posts = [];

(photos || []).forEach((photoUrl) => {
  const newPost = {
    id: shortid.generate(),
    userId: user.id,
    type: "photo",
    mediaUrl: photoUrl,
caption: `${user.firstName || "Someone"} just joined RomBuzz ✨ Let's Buzz!`,
    visibility: "public", // visible on LetsBuzz + profile
    createdAt: Date.now(),
    likes: [],
    comments: [],
    reactions: {},
  };
  db.data.posts.push(newPost);
});

await db.write();

// ✅ Notify all matched users about new posts
if (!db.data.matches) db.data.matches = [];
if (!db.data.notifications) db.data.notifications = [];

const matchedUsers = db.data.matches
  .filter(
    (m) =>
      (m.user1 === user.id || m.user2 === user.id) &&
      m.status === "matched"
  )
  .map((m) => (m.user1 === user.id ? m.user2 : m.user1));

for (const matchId of matchedUsers) {
  const notif = {
    id: shortid.generate(),
    type: "new_post",
    from: user.id,
    to: matchId,
    message: `${user.firstName || "Someone"} just shared new photos! 💫`,
    createdAt: Date.now(),
    read: false,
    link: "/letsbuzz", // where they'll be directed when clicked
  };
  db.data.notifications.push(notif);

  // ✅ Emit real-time socket event if the matched user is online
  if (io) {
    io.to(matchId).emit("notification:new_post", notif);
  }
}

await db.write();

res.json(baseSanitizeUser(user));

  } catch (err) {
    console.error("❌ /api/profile/complete failed:", err);
    res.status(500).json({ error: "Server error completing profile" });
  }
});



/* ======================
   DIRECT EMAIL SIGNUP 
====================== */
app.post('/api/auth/direct-signup', async (req, res) => {
  try {
    const { email, firstName, lastName, dob, gender, password } = req.body;
    if (!email || !firstName || !lastName || !dob || !gender || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    await db.read();
const emailLower = String(email || "").trim().toLowerCase();
const exists = db.data.users.find(u => (u.email || "").toLowerCase() === emailLower);
    if (exists) return res.status(400).json({ error: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);

    const user = {
      id: shortid.generate(),
      firstName,
      lastName,
      dob,
      gender,
      email: email.toLowerCase(),
      passwordHash: hash,
      bio: '',
      avatar: '',
      location: null,
      visibility: 'active',
      media: [],
      posts: [],
      interests: [],
      hobbies: [],
      favorites: [],
      createdAt: Date.now(),
      visibilityMode: 'auto',
      fieldVisibility: {
        age: 'public', height: 'public', city: 'public', orientation: 'public',
        interests: 'public', hobbies: 'public', likes: 'public', dislikes: 'public',
        lookingFor: 'public', voiceIntro: 'public', photos: 'matches'
      },
      nameChangedAt: 0,
      pendingEmailChange: null,
    };

    db.data.users.push(user);
    await db.write();

const token = signToken({ id: user.id, email: user.email });
    res.json({ token, user: baseSanitizeUser(user) });
  } catch (err) {
    console.error('❌ direct-signup error:', err);
    res.status(500).json({ error: 'Failed to register directly' });
  }
});

// =======================
// 🔐 AUTH MIDDLEWARE
// =======================
function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id, email: decoded.email };
    next();
  } catch (err) {
    console.error('Auth error:', err.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
// ----------------------
// ✅ Current user (for App.jsx restore)
// ----------------------
app.get('/api/users/me', authMiddleware, async (req, res) => {
  await db.read();
  const u = (db.data.users || []).find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'User not found' });

  // Return a safe user object (no password/hash)
  const safe = { ...u };
  delete safe.password;
  delete safe.passwordHash;
  delete safe.emailVerificationCode;
  res.json(safe);
});
// =======================
// 📸 UPLOAD AVATAR (with Cloudinary)
// =======================
app.post("/api/upload-avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "rombuzz/avatars",
      resource_type: "image",
      transformation: [
        { width: 400, height: 400, crop: "fill", gravity: "face", radius: "max" },
      ],
    });

    fs.unlink(req.file.path, () => {}); // cleanup local tmp file

    res.json({ url: result.secure_url, public_id: result.public_id });
  } catch (err) {
    console.error("❌ Avatar upload failed:", err);
    res.status(500).json({ error: "Avatar upload failed" });
  }
});


// =======================
// EMAIL CHANGE (2-step)
// =======================

// Step 1 — request code to NEW email
app.post('/api/account/request-email-change', authMiddleware, async (req, res) => {
  try {
    const { newEmail } = req.body || {};
    if (!newEmail) return res.status(400).json({ error: 'newEmail is required' });

    await db.read();
    const u = db.data.users.find(x => x.id === req.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });

    const emailLower = newEmail.toLowerCase();

    // Prevent using an email that already exists
    const exists = db.data.users.some(x => x.email.toLowerCase() === emailLower);
    if (exists) return res.status(409).json({ error: 'Email already in use' });

    // Generate a 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000; // 10 minutes

    u.pendingEmailChange = { email: emailLower, code, expires };
    await db.write();

    // Send (or log in dev)
    if (!process.env.SENDGRID_API_KEY) {
      console.log(`📧 [DEV] Email-change code for ${emailLower}: ${code}`);
      return res.json({ success: true, dev: true });
    } else {
      const msg = {
        to: emailLower,
        from: process.env.FROM_EMAIL || 'myprojectthisyear2025@gmail.com',
        subject: 'Confirm your new email',
        text: `Your code is ${code}. It expires in 10 minutes.`,
        html: `<p>Your code is <strong>${code}</strong>. It expires in 10 minutes.</p>`,
      };
      await sgMail.send(msg);
      return res.json({ success: true });
    }
  } catch (e) {
    console.error('request-email-change error', e);
    res.status(500).json({ error: 'Failed to send code' });
  }
});

// Step 2 — confirm with code (and apply the email)
app.post('/api/account/confirm-email-change', authMiddleware, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: 'code required' });

    await db.read();
    const u = db.data.users.find(x => x.id === req.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });

    const pending = u.pendingEmailChange;
    if (!pending) return res.status(400).json({ error: 'No email change pending' });

    if (pending.expires < Date.now()) {
      u.pendingEmailChange = null;
      await db.write();
      return res.status(400).json({ error: 'Code expired' });
    }

    if (pending.code !== code) {
      return res.status(400).json({ error: 'Invalid code' });
    }

    // apply the new email
    u.email = pending.email;
    u.pendingEmailChange = null;
    await db.write();

    res.json({ success: true, email: u.email });
  } catch (e) {
    console.error('confirm-email-change error', e);
    res.status(500).json({ error: 'Failed to confirm email change' });
  }
});

// DELETE entire conversation (soft-delete for current user)
// scope=me (default) -> add myId to hiddenFor for every message
app.delete("/api/chat/rooms/:roomId", authMiddleware, async (req, res) => {
  const { roomId } = req.params;
  const { scope = "me" } = req.query;

  const doc = await getRoomDoc(roomId);
  if (!doc) return res.status(404).json({ error: "not found" });

  // validate membership
  const { a, b } = (function getPeersFromRoomId(roomId) {
    const [x, y] = String(roomId).split("_");
    return { a: x, b: y };
  })(roomId);

  if (![a, b].includes(req.user.id)) {
    return res.status(403).json({ error: "forbidden" });
  }

  if (scope === "me") {
    const myId = req.user.id;
    (doc.list || []).forEach((m) => {
      m.hiddenFor = m.hiddenFor || [];
      if (!m.hiddenFor.includes(myId)) m.hiddenFor.push(myId);
    });
    await db.write();
    return res.json({ ok: true, scope: "me" });
  }

  return res.status(400).json({ error: "invalid scope" });
});

// =======================
// 🔔 NOTIFICATIONS ROUTES
// =======================

// Get all notifications for current user
// GET all notifications for current user (enriched with deep links)
app.get("/api/notifications", authMiddleware, async (req, res) => {
  await db.read();

  // only mine
  const mine = db.data.notifications.filter((n) => n.toId === req.user.id);

  // Add a stable deep link if the notification doesn't already have one.
  const enrich = (n) => {
    if (n.href && typeof n.href === "string" && n.href.startsWith("/")) return n;

    const out = { ...n };
    switch (n.type) {
      case "wingman":
        out.href = "/discover";
        break;

      // Profile-centric notifications
      case "match":
      case "buzz":
      case "like":
        if (n.fromId) out.href = `/viewprofile/${n.fromId}`;
        break;

      // Post-centric notifications
      case "comment":
      case "reaction":
      case "new_post":
      case "share": {
        const postId  = n.postId   || n.entityId || null;
        const ownerId = n.postOwnerId || n.ownerId || n.fromId || null; // best-effort
        if (postId && ownerId) {
          out.href = `/viewprofile/${ownerId}?post=${postId}`;
        } else if (n.fromId) {
          out.href = `/viewprofile/${n.fromId}`;
        }
        break;
      }

      default:
        out.href = "/notifications";
    }
    return out;
  };

  const list = mine.map(enrich)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json(list);
});


/* ======================
   USER SETTINGS
====================== */
const DEFAULT_SETTINGS = {
  discoverVisible: true,      // show me in Discover
  blurDefault: true,          // blur my profile by default
  showLastSeen: true,         // show last active
  incognitoMode: false,       // temporary hide (frontend can add timers)
  notifications: {
    likes: true,
    messages: true,
    buzz: true,
    wingman: true,
    email: false,
  },
  wingman: {
    tone: "flirty",           // funny | flirty | chill | romantic | friendly
    autoSuggest: true,
    priority: "interests",    // interests | humor | looks | proximity
  },
  theme: "rombuzz",           // light | dark | rombuzz
  distanceUnit: "km",         // km | miles
  radius: 50,                 // default discover radius
  language: "en",
};

app.get("/api/settings", authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: "User not found" });
  const settings = { ...DEFAULT_SETTINGS, ...(u.settings || {}) };
  res.json({ settings });
});

app.put("/api/settings", authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: "User not found" });

  // shallow + nested merge, whitelist keys
  const body = req.body || {};
  const next = { ...DEFAULT_SETTINGS, ...(u.settings || {}) };

  // top-level
  for (const k of [
    "discoverVisible",
    "blurDefault",
    "showLastSeen",
    "incognitoMode",
    "theme",
    "distanceUnit",
    "radius",
    "language",
  ]) {
    if (k in body) next[k] = body[k];
  }

  // nested: notifications
  if (body.notifications && typeof body.notifications === "object") {
    next.notifications = { ...DEFAULT_SETTINGS.notifications, ...next.notifications, ...body.notifications };
  }
  // nested: wingman
  if (body.wingman && typeof body.wingman === "object") {
    next.wingman = { ...DEFAULT_SETTINGS.wingman, ...next.wingman, ...body.wingman };
  }

  u.settings = next;
  await db.write();
  res.json({ settings: next });
});
// =======================
// ❤️ SOCIAL STATS (liked / likedYou / matches) - FIXED
// =======================
app.get("/api/users/social-stats", authMiddleware, async (req, res) => {
  await db.read();
  const myId = req.user.id;

  // Ensure arrays exist
  db.data.likes   ||= [];
  db.data.matches ||= [];

  // Who I liked
  const liked = db.data.likes
    .filter((l) => l.from === myId)
    .map((l) => l.to);

  // Who liked me
  const likedYou = db.data.likes
    .filter((l) => l.to === myId)
    .map((l) => l.from);

  // Matches from db.data.matches
  let matches = (db.data.matches || [])
    .filter(m =>
      (m.userA === myId || m.userB === myId) ||
      (Array.isArray(m.users) && m.users.includes(myId))
    )
    .map(m => {
      if (Array.isArray(m.users)) {
        const [a, b] = m.users;
        return a === myId ? b : a;
      }
      return m.userA === myId ? m.userB : m.userA;
    });

  // Fallback: include mutual likes if no explicit match records yet
  if (!matches.length) {
    const mutual = liked.filter((id) => likedYou.includes(id));
    matches = Array.from(new Set([...matches, ...mutual]));
  }

  res.json({
    likedCount: liked.length,
    likedYouCount: likedYou.length,
    matchCount: matches.length,
    liked,
    likedYou,
    matches,
  });
});

// =======================
// 🤖 AI WINGMAN NOTIFICATIONS
// =======================

// Generate an AI Wingman notification for a user
app.post("/api/notifications/wingman", authMiddleware, async (req, res) => {
  await db.read();
  const { message } = req.body;
  const toId = req.user.id;

  const payload = {
    fromId: "system",
    type: "wingman",
    message: message || "Your AI Wingman has something for you 💡",
      href: `/letsbuzz`,

  };

// ======================
// GLOBAL NOTIFICATION HANDLER
// ======================
async function sendNotification(toId, payload) {
  try {
    await db.read();
    db.data.notifications ||= [];

    const notif = {
      id: shortid.generate(),
      to: String(toId),
      from: payload.fromId || null,
      type: payload.type || "generic",
      message: payload.message || "",
      href: payload.href || null,
      entity: payload.entity || null,
      entityId: payload.entityId || null,
      postId: payload.postId || null,
      postOwnerId: payload.postOwnerId || null,
      streak: payload.streak || null,
      createdAt: Date.now(),
      read: false,
    };

    db.data.notifications.push(notif);
    await db.write();

    // Try emit via Socket.IO to recipient (live badge)
    const sid = onlineUsers[toId];
    if (sid) {
      io.to(sid).emit("notification", notif);
    }

    console.log("🔔 Notification →", toId, notif.type, notif.message);
    return notif;
  } catch (e) {
    console.error("sendNotification failed:", e);
  }
}
  res.json({ success: true, message: "Wingman notification sent" });
});

// Mark a notification as read
app.patch("/api/notifications/:id/read", authMiddleware, async (req, res) => {
  await db.read();
  const notif = db.data.notifications.find((n) => n.id === req.params.id);
  if (!notif) return res.status(404).json({ error: "Not found" });
  notif.read = true;
  await db.write();
  res.json({ success: true });
});

// Delete a notification
app.delete("/api/notifications/:id", authMiddleware, async (req, res) => {
  await db.read();
  db.data.notifications = db.data.notifications.filter(
    (n) => n.id !== req.params.id
  );
  await db.write();
  res.json({ success: true });
});

// Block a user from sending notifications
app.post("/api/notifications/block/:userId", authMiddleware, async (req, res) => {
  await db.read();
  const uid = req.user.id;
  db.data.blocks = db.data.blocks || [];
  const already = db.data.blocks.find(
    (b) => b.blocker === uid && b.blocked === req.params.userId
  );
  if (!already) {
    db.data.blocks.push({ blocker: uid, blocked: req.params.userId });
    await db.write();
  }
  res.json({ success: true });
});


/* ======================
   GOOGLE LOGIN
====================== */
/*
app.post('/api/auth/google', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Google token required' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();

    await db.read();
    let user = db.data.users.find(u => u.email === email);

    if (!user) {
    user = {
  id: shortid.generate(),
  firstName: payload.given_name || '',
  lastName: payload.family_name || '',
  email,
  passwordHash: '',
  bio: '',
  avatar: payload.picture || '',
  location: null,
  visibility: 'active',
  media: [],
  posts: [],
  interests: [],
  hobbies: [],
  favorites: [],
  createdAt: Date.now(),

  // ✅ add these
  visibilityMode: 'auto',
  fieldVisibility: {
    age: 'public', height: 'public', city: 'public', orientation: 'public',
    interests: 'public', hobbies: 'public', likes: 'public', dislikes: 'public',
    lookingFor: 'public', voiceIntro: 'public', photos: 'matches'
  },

  // NEW
  nameChangedAt: 0,
  pendingEmailChange: null,
};


      db.data.users.push(user);
      await db.write();
    }

const jwtToken = signToken({ id: user.id, email: user.email });
res.json({ token: jwtToken, user: baseSanitizeUser(user) });

  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Google login failed' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json({ user: baseSanitizeUser(user) });
});
*/

// ✅ Extended registration route for verified users (Register.jsx)
app.post("/api/auth/register-full", async (req, res) => {
  await db.read();
  const {
    email,
    firstName,
    lastName,
    password,
    gender,
    dob,
    lookingFor,
    interestedIn,
    preferences,
    visibilityMode,
    interests,
    avatar,
    photos,
    phone,
    voiceUrl,
  } = req.body;

  if (!email || !password || !firstName || !lastName) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  let user = db.data.users.find((u) => u.email === email);
  if (user) {
    return res.status(400).json({ error: "Account already exists." });
  }

  user = {
    id: shortid.generate(),
    email,
    firstName,
    lastName,
    password,
    gender,
    dob,
    lookingFor,
    interestedIn,
    preferences: preferences || {},
    visibilityMode: visibilityMode || "auto",
    interests: interests || [],
    avatar: avatar || "",
    photos: photos || [],
    phone: phone || "",
    voiceUrl: voiceUrl || "",
    createdAt: Date.now(),
    verified: true,
    premium: false,
  };

  db.data.users.push(user);
  await db.write();

  const token = signToken({ id: user.id, email: user.email });
res.json({ token, user: baseSanitizeUser(user) });

});

// =======================
// 📸 MICROBUZZ SELFIE UPLOAD
// =======================
app.post("/api/microbuzz/selfie", authMiddleware, upload.single("selfie"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No selfie provided" });

    const uploadResult = await cloudinary.uploader.upload(req.file.path, {
      folder: "rombuzz/selfies",
      resource_type: "image",
      transformation: [{ width: 320, height: 320, crop: "fill", gravity: "face" }],
    });

    // cleanup temp file
    fs.unlink(req.file.path, () => {});

    return res.json({ url: uploadResult.secure_url });
  } catch (err) {
    console.error("❌ MicroBuzz selfie upload failed:", err);
    return res.status(500).json({ error: "Upload failed" });
  }
});

/* =======================
// 💬 MICROBUZZ BUZZ REQUEST (with match detection + selfie + match save)
// =======================
app.post("/api/microbuzz/buzz", authMiddleware, async (req, res) => {
  const { toId } = req.body || {};
  if (!toId) return res.status(400).json({ error: "toId required" });

  await db.read();
  const fromId = req.user.id;

  // Ensure arrays exist
  db.data.likes ||= [];
  db.data.matches ||= [];
  db.data.notifications ||= [];

  // Prevent self-buzz
  if (fromId === toId) return res.status(400).json({ error: "Cannot buzz yourself" });

  // Check if match already exists
  const alreadyMatched = db.data.matches.some(
    (m) =>
      (m.userA === fromId && m.userB === toId) ||
      (m.userA === toId && m.userB === fromId)
  );
  if (alreadyMatched) {
    return res.json({ matched: true, alreadyMatched: true });
  }

  // Check if user already buzzed
  const alreadyLiked = db.data.likes.some(
    (l) => l.from === fromId && l.to === toId
  );
  if (alreadyLiked) {
    return res.json({ alreadyLiked: true });
  }

  // Save buzz (like)
  db.data.likes.push({ from: fromId, to: toId, createdAt: Date.now() });
  await db.write();

  // ✅ Check for mutual buzz
  const mutual = db.data.likes.find((l) => l.from === toId && l.to === fromId);
  if (mutual) {
    // Save match
    db.data.matches.push({ userA: fromId, userB: toId, createdAt: Date.now() });
    await db.write();

    // Notify both sides
    await global.sendNotification(toId, {
      fromId,
      type: "match",
      message: "🎉 It's a match! You both buzzed each other!",
    });
    await global.sendNotification(fromId, {
      fromId: toId,
      type: "match",
      message: "🎉 It's a match! You both buzzed each other!",
    });

    // ✅ Emit realtime match event
    const sidA = onlineUsers[fromId];
    const sidB = onlineUsers[toId];
    if (sidA) io.to(sidA).emit("match", { otherUserId: toId });
    if (sidB) io.to(sidB).emit("buzz_request", { fromId });

    return res.json({ matched: true });
  }

  // ✅ Notify target user via socket (buzz_request)
  const sid = onlineUsers[toId];
  if (sid) {
    io.to(sid).emit("buzz_request", { fromId });
  }

  await global.sendNotification(toId, {
    fromId,
    type: "buzz",
    message: "Someone buzzed you on MicroBuzz 👋",
  });

  return res.json({ success: true });
});
*/

// =======================
// ⚡ MICROBUZZ ACTIVATE / NEARBY / DEACTIVATE
// =======================

// In-memory presence list (short-lived)
if (!db.data.microbuzz) db.data.microbuzz = [];

// 1️⃣ Activate presence (store selfie + coords)
app.post("/api/microbuzz/activate", authMiddleware, async (req, res) => {
  try {
    console.log("📸 /api/microbuzz/activate → RAW BODY:", req.body);

    // Validate body safely
    const { lat, lng, selfieUrl } = req.body || {};
    const latNum = parseFloat(lat);
    const lngNum = parseFloat(lng);

    if (isNaN(latNum) || isNaN(lngNum) || !selfieUrl) {
      console.warn("⚠️ Invalid input:", { lat, lng, selfieUrl });
      return res.status(400).json({ error: "Invalid or missing lat/lng/selfieUrl" });
    }

    // Make sure DB is ready and array exists
    await db.read();
    if (!db.data) db.data = {};
    if (!Array.isArray(db.data.microbuzz)) db.data.microbuzz = [];

    // Remove previous record
    db.data.microbuzz = db.data.microbuzz.filter((r) => r.userId !== req.user.id);

    // ✅ Push new record (with tiny offset so both tabs see each other)
let offsetLat = 0;
let offsetLng = 0;

// Apply small random offset (≈ ±50 m) for local testing
if (process.env.NODE_ENV !== "production") {
  offsetLat = (Math.random() - 0.5) * 0.0005;
  offsetLng = (Math.random() - 0.5) * 0.0005;
}

const record = {
  userId: req.user.id,
  selfieUrl,
  lat: latNum + offsetLat,
  lng: lngNum + offsetLng,
  updatedAt: Date.now(),
};

db.data.microbuzz.push(record);


    console.log("✅ Stored MicroBuzz record:", record);
    await db.write();

    res.json({ success: true });
  } catch (err) {
    console.error("❌ /api/microbuzz/activate server error:", err);
    res.status(500).json({ error: "Activate failed: " + (err.message || "unknown") });
  }
});


// 2️⃣ List nearby active users (within ~1 km)
app.get("/api/microbuzz/nearby", authMiddleware, async (req, res) => {
  const lat = parseFloat(req.query.lat);
  const lng = parseFloat(req.query.lng);
  const radiusKm = parseFloat(req.query.radius || "1");

  if (isNaN(lat) || isNaN(lng)) return res.status(400).json({ error: "lat/lng required" });

  await db.read();
  const now = Date.now();
  const users = (db.data.microbuzz || [])
    .filter((u) => u.userId !== req.user.id && now - u.updatedAt < 5 * 60 * 1000) // active < 5 min
    .map((u) => {
      const d = Math.sqrt((u.lat - lat) ** 2 + (u.lng - lng) ** 2) * 111; // km approx
      return { id: u.userId, selfieUrl: u.selfieUrl, distanceMeters: d * 1000 };
    })
// Always show users even if at same spot (for local testing)
.filter((u) => u.distanceMeters <= radiusKm * 1000 || process.env.NODE_ENV !== "production");

  res.json({ users });
});

// 3️⃣ Deactivate (remove presence)
app.post("/api/microbuzz/deactivate", authMiddleware, async (req, res) => {
  await db.read();
  db.data.microbuzz = (db.data.microbuzz || []).filter((r) => r.userId !== req.user.id);
  await db.write();
  res.json({ success: true });
});
// =======================
// 💬 MICROBUZZ BUZZ REQUEST (with match detection + selfie + match save)
// =======================
app.post("/api/microbuzz/buzz", authMiddleware, async (req, res) => {
  const { toId, confirm } = req.body || {};
  if (!toId) return res.status(400).json({ error: "toId required" });

  await db.read();
  const fromId = req.user.id;

  if (!Array.isArray(db.data.microbuzz_buzzes)) db.data.microbuzz_buzzes = [];
  if (!Array.isArray(db.data.matches)) db.data.matches = [];

  // Check if the other user already buzzed this user
  const existing = db.data.microbuzz_buzzes.find(
    (b) => b.fromId === toId && b.toId === fromId
  );

// ✅ Reverse buzz exists
if (existing) {
  if (confirm === true) {
    console.log(`💥 MicroBuzz match (confirmed) between ${fromId} ↔ ${toId}`);

    // Remove both buzz records
    db.data.microbuzz_buzzes = db.data.microbuzz_buzzes.filter(
      (b) =>
        !(
          (b.fromId === fromId && b.toId === toId) ||
          (b.fromId === toId && b.toId === fromId)
        )
    );

    // ✅ Save permanent match record
    const already = db.data.matches.find(
      (m) =>
        (Array.isArray(m.users) &&
          m.users.includes(fromId) &&
          m.users.includes(toId)) ||
        (m.a === fromId && m.b === toId) ||
        (m.a === toId && m.b === fromId)
    );
    if (!already) {
      db.data.matches.push({
        users: [fromId, toId],
        type: "microbuzz",
        createdAt: Date.now(),
      });
      console.log("💾 Match saved to db.data.matches (users:[A,B])");
    }

    await db.write();

    // 🔁 Notify both users to open each other's profile
    const fromUser = (db.data.microbuzz || []).find((u) => u.userId === fromId);
    const toUser = (db.data.microbuzz || []).find((u) => u.userId === toId);

    [fromId, toId].forEach((uid) => {
      const otherId = uid === fromId ? toId : fromId;
      const otherSelfie =
        uid === fromId
          ? (toUser ? toUser.selfieUrl : null)
          : (fromUser ? fromUser.selfieUrl : null);

      if (onlineUsers[uid]) {
        io.to(String(uid)).emit("buzz_match_open_profile", {
          otherUserId: otherId,
          selfieUrl: otherSelfie,
        });
      }
    });

    return res.json({ matched: true });
  } else {
    // 🚫 Reverse buzz exists but confirm not yet given → notify recipient to confirm
    console.log(`📨 ${fromId} buzzed ${toId}, reverse exists — asking for confirmation`);
    if (onlineUsers[toId]) {
      io.to(String(toId)).emit("buzz_request", {
        fromId,
        type: "microbuzz",
        message: "Someone nearby buzzed you!",
        selfieUrl:
          (db.data.microbuzz || []).find((u) => u.userId === fromId)?.selfieUrl ||
          (db.data.users || []).find((u) => u.id === fromId)?.avatar ||
          "",
        name:
          (db.data.users || []).find((u) => u.id === fromId)?.firstName ||
          "Someone nearby",
      });
    }
    return res.json({ pending: true, requiresConfirm: true });
  }
}


  // 🚀 Otherwise, store new buzz and notify recipient
  const existingBuzz = db.data.microbuzz_buzzes.find(
    (b) => b.fromId === fromId && b.toId === toId
  );
  if (!existingBuzz) {
    db.data.microbuzz_buzzes.push({ fromId, toId, time: Date.now() });
    await db.write();
  }

  // ✅ Notify recipient (with selfie + name)
  const fromPresence =
    (db.data.microbuzz_presence || []).find((u) => u.userId === fromId) ||
    (db.data.microbuzz || []).find((u) => u.userId === fromId);
  const senderProfile = (db.data.users || []).find((u) => u.id === fromId);

  if (onlineUsers[toId]) {
    io.to(String(toId)).emit("buzz_request", {
      fromId,
      type: "microbuzz",
      message: "Someone nearby buzzed you!",
      selfieUrl:
        fromPresence?.selfieUrl ||
        senderProfile?.avatar ||
        senderProfile?.profilePic ||
        "",
      name:
        senderProfile?.firstName ||
        senderProfile?.name ||
        "Someone nearby",
    });

    console.log(
      `⚡ MicroBuzz buzz_request emitted ${fromId} → ${toId} (✅ includes selfie + name)`
    );
  }

  res.json({ success: true });
});

// =======================
// 💬 BUZZ COMMENTS (fetch filtered for owner/commenter only)
// =======================
app.get("/api/buzz/posts/:id/comments", authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    await db.read();

    // Locate the post
    const post = (db.data.buzz_posts || []).find((p) => p.id === id);
    if (!post) return res.status(404).json({ error: "Post not found" });

    // All comments for this post
    const allComments = (db.data.buzz_comments || []).filter((c) => c.postId === id);
    const viewerId = req.user.id;

    // 🔒 Show comments only if viewer is either:
    // 1. The post owner, OR
    // 2. The comment author
    const visible = allComments.filter((c) => {
      const visibleTo = c.visibleTo || [post.userId, c.userId]; // Fallback for old comments
      return visibleTo.includes(viewerId);
    });

    // Enrich with author info
    const withUser = visible.map((c) => ({
      ...c,
      author: db.data.users.find((u) => u.id === c.userId) || null,
    }));

    res.json({ comments: withUser });
  } catch (err) {
    console.error("Comments fetch error:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// =======================
// 📍 MEET IN MIDDLE / SAFE MEET FEATURE
// =======================

// 🔧 Ensure LowDB root + geo array exist safely
if (!db.data) db.data = {};
if (!db.data.geo) db.data.geo = [];

// 1️⃣ Save last known location (client can ping this)
app.post("/api/geo/save", authMiddleware, async (req, res) => {
  const { lat, lng } = req.body || {};
  if (typeof lat !== "number" || typeof lng !== "number")
    return res.status(400).json({ error: "lat/lng required" });

  await db.read();
  db.data.geo = db.data.geo.filter((g) => g.userId !== req.user.id);
  db.data.geo.push({ userId: req.user.id, lat, lng, updatedAt: Date.now() });
  await db.write();

  res.json({ success: true });
});

// 2️⃣ Get approximate location of a user
app.get("/api/geo/approx", authMiddleware, async (req, res) => {
  const userId = req.query.userId;
  await db.read();
  const rec = (db.data.geo || []).find((g) => g.userId === userId);
  if (!rec) return res.status(404).json({ error: "no location" });
  res.json({ lat: rec.lat, lng: rec.lng, updatedAt: rec.updatedAt });
});


// 3️⃣ Suggest fair midpoint places (OpenStreetMap version — no API key needed)
app.post("/api/meet/suggest", authMiddleware, async (req, res) => {
  try {
    const { a, b } = req.body || {};
    if (!a || !b || typeof a.lat !== "number" || typeof b.lat !== "number") {
      return res.status(400).json({ error: "Both coordinate objects required" });
    }

    // 🧭 Midpoint
    const midLat = (a.lat + b.lat) / 2;
    const midLng = (a.lng + b.lng) / 2;

    // 📍 Define search radius (in meters)
    const radius = 1500;

    // 🍷 Place categories we care about
    const query = `
      [out:json];
      (
        node["amenity"~"cafe|restaurant|bar|pub|park|cinema"](around:${radius},${midLat},${midLng});
        way["amenity"~"cafe|restaurant|bar|pub|park|cinema"](around:${radius},${midLat},${midLng});
      );
      out center;
    `;

    const url = "https://overpass-api.de/api/interpreter";
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `data=${encodeURIComponent(query)}`,
    });

    const data = await response.json();

    const places = (data.elements || [])
      .map((el) => ({
        name:
          el.tags?.name ||
          el.tags?.brand ||
          el.tags?.amenity ||
          "Unnamed Spot",
        lat: el.lat || el.center?.lat,
        lng: el.lon || el.center?.lon,
        vicinity:
          el.tags?.addr_full ||
          el.tags?.addr_street ||
          el.tags?.addr_city ||
          "",
        type: el.tags?.amenity || "place",
      }))
      .filter((p) => p.lat && p.lng);

    console.log(
      `✅ /api/meet/suggest midpoint ${midLat}, ${midLng} — ${places.length} spots found`
    );

    res.json({ midpoint: { lat: midLat, lng: midLng }, places });
  } catch (err) {
    console.error("❌ meet-suggest error:", err);
    res.status(500).json({ error: "meet-suggest failed" });
  }
});


// 4️⃣ Log a chosen place (and optionally notify peer)
app.post("/api/meet/choose", authMiddleware, async (req, res) => {
  const { roomId, place, toId } = req.body || {};
  if (!place) return res.status(400).json({ error: "place required" });

  io.to(String(toId)).emit("meet:chosen", { place, from: req.user.id });
  res.json({ success: true });
});


// ======================
// FULL PROFILE (with media)
// ======================
app.get('/api/profile/full', authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({
    user: {
      ...baseSanitizeUser(u),
      media: u.media || [],
      posts: u.posts || []
    }
  });
});

// ===============================
// 🚫 BLOCK / UNBLOCK SYSTEM
// ===============================
app.get('/api/blocks', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const blocks = (db.data.blocks || [])
    .filter(b => b.blocker === me)
    .map(b => {
      const target = db.data.users.find(u => u.id === b.blocked);
      return target ? { id: target.id, firstName: target.firstName, lastName: target.lastName } : null;
    })
    .filter(Boolean);
  res.json({ blocks });
});

app.post('/api/blocks/:userId', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const targetId = req.params.userId;
  if (me === targetId) return res.status(400).json({ error: "Cannot block yourself" });

  db.data.blocks = db.data.blocks || [];
  const already = db.data.blocks.find(b => b.blocker === me && b.blocked === targetId);
  if (already) return res.json({ success: true });

  db.data.blocks.push({ blocker: me, blocked: targetId, createdAt: Date.now() });
  await db.write();

  res.json({ success: true });
});

app.delete('/api/blocks/:userId', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const targetId = req.params.userId;
  db.data.blocks = (db.data.blocks || []).filter(b => !(b.blocker === me && b.blocked === targetId));
  await db.write();
  res.json({ success: true });
});

/* ======================
   USERS
====================== */
app.put('/api/users/me', authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });

 const allowed = [
  'firstName','lastName','dob','gender','name','bio','location','visibility','avatar','phone','email',
  'interests','favorites','orientation','hobbies',
  'vibe','filterVibe','premiumTier','settings',
  'visibilityMode','fieldVisibility' // ⬅️ add these
];




  // Normalize array-like fields
  const body = { ...(req.body || {}) };
  for (const k of ['interests', 'favorites', 'hobbies']) {
    if (k in body && !Array.isArray(body[k])) {
      // attempt to coerce from comma string
      if (typeof body[k] === 'string') {
        body[k] = body[k].split(',').map(s => s.trim()).filter(Boolean);
      } else {
        body[k] = [];
      }
    }
  }
// Validate vibes
if ('vibe' in body) {
  const v = String(body.vibe || '').toLowerCase();
  if (v && !PUBLIC_VIBES.has(v)) {
    return res.status(400).json({ error: 'vibe must be a PUBLIC option' });
  }
}
if ('filterVibe' in body) {
  const fv = String(body.filterVibe || '').toLowerCase();
  if (fv && !isAllowedVibeKey(fv)) {
    return res.status(400).json({ error: 'Invalid filterVibe' });
  }
}

  // --- Guard name change to once / 30 days ---
  const wantsNameChange = ('firstName' in body) || ('lastName' in body);
  if (wantsNameChange) {
    const now = Date.now();
    const last = Number(u.nameChangedAt || 0);
    const remaining = THIRTY_DAYS - (now - last);
    if (last && remaining > 0) {
      return res.status(429).json({
        error: `You can change your name again in ${msToDays(remaining)} day(s).`,
        retryInMs: remaining
      });
    }
  }

  // Apply whitelisted fields (except email—email uses the new 2-step flow)
  Object.keys(body).forEach(k => {
    if (k === 'email') return; // email is changed via /account/confirm-email-change
    if (allowed.includes(k)) u[k] = body[k];
  });

  // If we actually changed the name, stamp the date
  if (wantsNameChange) {
    u.nameChangedAt = Date.now();
  }

  
  await db.write();
  res.json({ user: baseSanitizeUser(u) });
});
// =======================
// 🔒 ACCOUNT DEACTIVATE / DELETE
// =======================

// Soft deactivate account
app.patch('/api/account/deactivate', authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'User not found' });

  u.visibility = 'deactivated';
  u.deactivatedAt = Date.now();
  await db.write();

  res.json({ success: true, message: 'Account deactivated', user: baseSanitizeUser(u) });
});

// Permanent account deletion
app.delete("/api/account/delete", authMiddleware, async (req, res) => {
  try {
    await db.read();
    db.data ||= {}; // ✅ ensure db.data exists even if undefined
    const uid = req.user.id;
    const user = (db.data.users || []).find((u) => u.id === uid);
    if (!user) return res.status(404).json({ error: "User not found" });

    const emailLower = (user.email || "").trim().toLowerCase();

    // ✅ Defensive array filtering
    const safeFilter = (arr, fn) => (Array.isArray(arr) ? arr.filter(fn) : []);

    // 🧹 Remove user and all associated data
    db.data.users = safeFilter(db.data.users, (u) => u.id !== uid);
    db.data.posts = safeFilter(db.data.posts, (p) => p.userId !== uid);
    db.data.notifications = safeFilter(
      db.data.notifications,
      (n) => n.to !== uid && n.from !== uid
    );
    db.data.matches = safeFilter(
      db.data.matches,
      (m) => !((m.users || []).includes(uid) || m.userA === uid || m.userB === uid)
    );
    db.data.messages = safeFilter(db.data.messages, (m) => m.from !== uid && m.to !== uid);
    db.data.likes = safeFilter(db.data.likes, (l) => l.from !== uid && l.to !== uid);
    db.data.blocks = safeFilter(db.data.blocks, (b) => b.blocker !== uid && b.blocked !== uid);
    db.data.matchStreaks = safeFilter(db.data.matchStreaks, (s) => s.user1 !== uid && s.user2 !== uid);
    db.data.reports = safeFilter(db.data.reports, (r) => r.fromId !== uid && r.toId !== uid);
    db.data.microbuzz = safeFilter(db.data.microbuzz, (mb) => mb.userId !== uid);

    // ✅ Clean verification & reset maps
    db.data.resetCodes ||= {};
    db.data.verificationCodes ||= {};
    delete db.data.resetCodes[emailLower];
    delete db.data.verificationCodes[emailLower];

    if (typeof verificationCodes === "object") delete verificationCodes[emailLower];
    if (typeof resetCodes === "object") delete resetCodes[emailLower];

    await db.write();

    console.log(`🗑️ Account deleted permanently for ${user.email}`);
    return res.json({
      success: true,
      message: "Account deleted permanently — you can now sign up again.",
    });
  } catch (err) {
    console.error("❌ Error deleting account:", err);
    return res.status(500).json({
      error: "Server error deleting account",
      details: err.message,
    });
  }
});



/* ----------------------
   Get current user info
----------------------- */
app.get("/api/users/me", authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const safeUser = { ...user };
  delete safeUser.password;
  delete safeUser.emailVerificationCode;
  res.json(safeUser);
});

/* ----------------------
   Update my current location (from client geolocation)
----------------------- */
app.post('/api/location', authMiddleware, async (req, res) => {
  const { lat, lng } = req.body || {};
  const latNum = Number(lat);
  const lngNum = Number(lng);
  if (!Number.isFinite(latNum) || !Number.isFinite(lngNum)) {
    return res.status(400).json({ error: 'lat & lng required' });
  }
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  u.location = { lat: latNum, lng: lngNum };
  await db.write();
  res.json({ ok: true, location: u.location });
});

// Social stats: likes given/received + matches (safe for legacy entries)
app.get(['/api/users/social', '/api/social-stats'], authMiddleware, async (req, res) => {
  await db.read();
  const myId = req.user.id;

  const likesGiven = (db.data.likes || []).filter(l => l.from === myId).length;
  const likesReceived = (db.data.likes || []).filter(l => l.to === myId).length;

  // ✅ Fix: safely handle both array-based and legacy match objects
  const matchesCount = (db.data.matches || []).filter(m => {
    if (Array.isArray(m.users)) return m.users.includes(myId);
    return m.a === myId || m.b === myId;
  }).length;
res.json({ likesGiven, likesReceived, matchesCount });
});

// ✅ New endpoint — list actual match profiles
app.get("/api/matches", authMiddleware, async (req, res) => {
 
  await db.read();
  const myId = req.user.id;
  const matches = (db.data.matches || []).filter((m) => {
    if (Array.isArray(m.users)) return m.users.includes(myId);
    return m.a === myId || m.b === myId;
  });

  const partnerIds = matches.map((m) => {
    if (Array.isArray(m.users)) {
      return m.users.find((id) => id !== myId);
    } else {
      return m.a === myId ? m.b : m.a;
    }
  });

  const uniqueIds = [...new Set(partnerIds)];
  const partners = db.data.users
    .filter((u) => uniqueIds.includes(u.id))
    .map((u) => baseSanitizeUser(u));

  res.json({ count: partners.length, matches: partners });
});


// -------------------------------
// 🔥 BuzzStreak (match streak API)
// -------------------------------
app.post('/api/matchstreak/:toId', authMiddleware, async (req, res) => {
  await db.read();
  const fromId = req.user.id;
  const { toId } = req.params;

  if (fromId === toId) {
    return res.status(400).json({ error: "Cannot buzz yourself" });
  }

  // Increment streak
  const s = incMatchStreakOut(db.data, fromId, toId);
  await db.write();

  // Optional: also send notification
  await sendNotification(toId, {
    fromId,
    type: "buzzstreak",
    message: `🔥 ${s.count} BuzzStreak from someone!`,
    href: `/viewprofile/${fromId}`,
  });

// --- BuzzStreak reward tiers ---
const BUZZSTREAK_REWARDS = [
  { day: 1,  reward: "🎉 Welcome back! Confetti" },
  { day: 3,  reward: "✨ Avatar Glow for 24h" },
  { day: 7,  reward: "⚡ 1-Day Discover Boost" },
  { day: 14, reward: "🏅 BuzzChampion Badge" },
  { day: 30, reward: "💖 LoyalHeart Title" },
  { day: 50, reward: "🌈 Premium Trial / Wingman Bonus" },
];

// --- Helper: apply actual effects to user when they reach a milestone ---
async function applyBuzzReward(userId, rewardObj) {
  await db.read();
  const u = db.data.users.find(x => x.id === userId);
  if (!u) return;

  switch (rewardObj.day) {
    case 3:
      // ✨ Avatar Glow for 24h
      u.effects = u.effects || {};
      u.effects.avatarGlow = { active: true, expiresAt: Date.now() + 24 * 60 * 60 * 1000 };
      await sendNotification(userId, {
        type: "buzzreward",
        message: "✨ Avatar Glow unlocked for 24 hours!",
      });
      break;

    case 7:
      // ⚡ Discover Boost for 24h
      u.boostActiveUntil = Date.now() + 24 * 60 * 60 * 1000;
      await sendNotification(userId, {
        type: "buzzreward",
        message: "⚡ Discover Boost activated for 1 day!",
      });
      break;

    case 14:
      // 🏅 Permanent badge
      u.badges = Array.isArray(u.badges) ? u.badges : [];
      if (!u.badges.includes("BuzzChampion")) u.badges.push("BuzzChampion");
      await sendNotification(userId, {
        type: "buzzreward",
        message: "🏅 You earned the BuzzChampion badge!",
      });
      break;

    case 30:
      // 💖 Title
      u.title = "LoyalHeart";
      await sendNotification(userId, {
        type: "buzzreward",
        message: "💖 You’ve unlocked the LoyalHeart title!",
      });
      break;

    case 50:
      // 🌈 Premium trial
      u.premiumTrialUntil = Date.now() + 3 * 24 * 60 * 60 * 1000;
      u.premiumTier = "plus";
      await sendNotification(userId, {
        type: "buzzreward",
        message: "🌈 Premium trial activated for 3 days!",
      });
      break;
  }

  await db.write();
}

// --- Check if user hits any milestone today ---
const hitReward = BUZZSTREAK_REWARDS.find(r => r.day === s.count);
if (hitReward) {
  await applyBuzzReward(fromId, hitReward);
}

// --- Next milestone info ---
const nextReward = BUZZSTREAK_REWARDS.find(r => r.day > s.count) || null;

res.json({
  success: true,
  streak: s,
  nextReward,
  rewardJustUnlocked: hitReward || null,
});

});

/* ======================
   AVATAR UPLOAD (Cloudinary preferred)
====================== */
// Option A: Frontend already uploaded to Cloudinary, send { avatarUrl }
app.post('/api/upload-avatar-url', authMiddleware, async (req, res) => {
  try {
    const { avatarUrl } = req.body || {};
    if (!avatarUrl) return res.status(400).json({ error: 'avatarUrl required' });

    await db.read();
    const u = db.data.users.find(x => x.id === req.user.id);
    if (!u) return res.status(404).json({ error: 'not found' });

       u.avatar = avatarUrl; // store absolute Cloudinary URL

    // ✅ also push to FaceBuzz gallery
    if (!u.media) u.media = [];
    u.media.unshift({
      id: shortid.generate(),
      url: avatarUrl,
      type: "image",
      caption: "facebuzz",
      privacy: "public",
      createdAt: Date.now()
    });

    await db.write();
    res.json({ url: avatarUrl, user: baseSanitizeUser(u) });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed to set avatar' });
  }
});

// Option B: Multipart upload -> backend uploads to Cloudinary (resource_type:auto)
app.post('/api/upload-avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file uploaded' });

    // Upload the file to Cloudinary
    const uploaded = await cloudinary.uploader.upload(req.file.path, {
      folder: process.env.CLOUDINARY_AVATAR_FOLDER || 'rombuzz_uploads/avatars',
      resource_type: 'auto',
      overwrite: true
    });

    await db.read();
    const u = db.data.users.find(x => x.id === req.user.id);
    if (!u) return res.status(404).json({ error: 'not found' });

    u.avatar = uploaded.secure_url;
    await db.write();

    // cleanup local file
    try { fs.unlinkSync(req.file.path); } catch {}

    res.json({ url: uploaded.secure_url, user: baseSanitizeUser(u) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'avatar upload failed' });
  }
});
// === Generic media upload (multipart) -> Cloudinary (resource_type:auto)
app.post('/api/upload-media-file', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file uploaded' });

    const uploaded = await cloudinary.uploader.upload(req.file.path, {
      folder: process.env.CLOUDINARY_MEDIA_FOLDER || 'rombuzz_uploads/posts',
      resource_type: 'auto',
      overwrite: true,
    });

    await db.read();
    const u = db.data.users.find(x => x.id === req.user.id);
    if (!u) return res.status(404).json({ error: 'User not found' });

    // stash in media library for the user
    const mediaItem = {
      id: shortid.generate(),
      url: uploaded.secure_url,
      type: (uploaded.resource_type === 'video') ? 'video' : 'image',
      caption: '',
      privacy: 'public',
      createdAt: Date.now(),
    };
    u.media ||= [];
    u.media.unshift(mediaItem);
    await db.write();

    // cleanup local temp file
    try { fs.unlinkSync(req.file.path); } catch {}

    res.json({
      ok: true,
      url: uploaded.secure_url,
      type: mediaItem.type,
      media: mediaItem,
    });
  } catch (err) {
    console.error('upload-media-file error:', err);
    res.status(500).json({ error: 'media upload failed' });
  }
});

/* ======================
   MEDIA (photo/video) — Cloudinary
====================== */
// Frontend typically uploads to Cloudinary unsigned and calls this to save metadata.
// You can also support multipart, uploading here if needed.
app.post('/api/upload-media', authMiddleware, async (req, res) => {
  try {
    const { fileUrl, type, caption } = req.body || {};
    if (!fileUrl) return res.status(400).json({ error: 'fileUrl is required' });

    await db.read();
    const user = db.data.users.find((u) => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const mediaItem = {
      id: shortid.generate(),
      url: fileUrl,
      type: type === 'video' ? 'video' : 'image',
      caption: caption || '',
      createdAt: Date.now()
    };
    if (!user.media) user.media = [];
    user.media.unshift(mediaItem);
    await db.write();

    res.json({ success: true, media: user.media });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});


/* ======================
   POSTS (status / reels)
====================== */


// ✅ Create a new post
app.post("/api/posts", authMiddleware, async (req, res) => {
  try {
    const { text, mediaUrl, type } = req.body || {};
    await db.read();

    const u = db.data.users.find((x) => x.id === req.user.id);
    if (!u) return res.status(404).json({ error: "User not found" });

    const decideType = () => {
      if (type) return type;
      if (!mediaUrl) return "text";
      const lower = mediaUrl.toLowerCase();
      if (
        /\.(mp4|mov|webm|ogg)$/.test(lower) ||
        mediaUrl.includes("/video/upload/")
      )
        return "video";
      return "image";
    };

    const post = {
      id: shortid.generate(),
      text: (text || "").trim(),
      mediaUrl: mediaUrl || "",
      type: decideType(),
      createdAt: Date.now(),
      visibility: "matches",
      reactions: {},
      comments: [],
    };

    if (!Array.isArray(u.posts)) u.posts = [];
    u.posts.unshift(post);
    await db.write();

    res.json({ post });
  } catch (e) {
    console.error("❌ Error creating post:", e);
    res.status(500).json({ error: "Could not create post" });
  }
});

// ✅ Get own posts
app.get("/api/posts/me", authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find((x) => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: "User not found" });
  const posts = (u.posts || []).slice().sort((a, b) => b.createdAt - a.createdAt);
  res.json({ posts });
});

// ✅ Get posts from matched users
app.get("/api/posts/matches", authMiddleware, async (req, res) => {
  await db.read();
  const myId = req.user.id;

  const myMatches = (db.data.matches || [])
    .filter((m) => Array.isArray(m.users) && m.users.includes(myId))
    .map((m) => m.users.find((id) => id !== myId));

  const posts = [];
  for (const otherId of myMatches) {
    const u = db.data.users.find((x) => x.id === otherId);
    if (!u || !Array.isArray(u.posts)) continue;
    for (const p of u.posts) {
      if (p.visibility === "matches") {
        posts.push({
          ...p,
          user: baseSanitizeUser(u),
        });
      }
    }
  }

  posts.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ posts });
});
// ✅ Get only video/reel posts from matched users
app.get("/api/reels", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const myId = req.user.id;

    const myMatches = (db.data.matches || [])
      .filter((m) => Array.isArray(m.users) && m.users.includes(myId))
      .map((m) => m.users.find((id) => id !== myId));

    const reels = [];
    for (const otherId of myMatches) {
      const u = db.data.users.find((x) => x.id === otherId);
      if (!u || !Array.isArray(u.posts)) continue;
      for (const p of u.posts) {
        const isVideo =
          p.type === "video" ||
          p.type === "reel" ||
          /\.(mp4|mov|webm|ogg)$/i.test(p.mediaUrl || "");
        if (isVideo) {
          reels.push({
            ...p,
            user: baseSanitizeUser(u),
          });
        }
      }
    }

    reels.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ posts: reels });
  } catch (err) {
    console.error("❌ Error fetching reels:", err);
    res.status(500).json({ error: "failed to load reels" });
  }
});


// ===================================================
// 🏠 FEED ENDPOINT — show matched users’ posts & reels
// ===================================================
app.get("/api/feed", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const myId = req.user.id;

    // find all match pairs that include me
    const myMatches = (db.data.matches || [])
      .filter(m => Array.isArray(m.users) && m.users.includes(myId))
      .map(m => m.users.find(id => id !== myId));

    const feed = [];

    for (const otherId of myMatches) {
      const u = db.data.users.find(x => x.id === otherId);
      if (!u || !Array.isArray(u.posts)) continue;

      for (const p of u.posts) {
        // include both image and video posts, visibility "matches" or "public"
        if (["matches", "public"].includes(p.visibility)) {
          feed.push({
            ...p,
            user: baseSanitizeUser(u),
          });
        }
      }
    }

    // newest first
    feed.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ posts: feed });
  } catch (err) {
    console.error("❌ Feed fetch failed:", err);
    res.status(500).json({ error: "failed to load feed" });
  }
});

// =======================
// 📤 AUTHENTICATED MEDIA UPLOAD (used by Create Buzz & Story uploads)
// =======================
app.post("/api/upload-media-file", authMiddleware, async (req, res) => {
  try {
    const file =
      (req.files && req.files.file) ||
      (req.file ? req.file : null);

    if (!file) {
      return res.status(400).json({ ok: false, error: "No file uploaded" });
    }

    const userId = req.user.id; // ✅ from authMiddleware

    // --- Cloudinary upload ---
    const { v2: cloudinary } = require("cloudinary");
    const uploadRes = await cloudinary.uploader.upload(
      file.tempFilePath || file.path,
      {
        folder: "rombuzz_uploads",
        resource_type: "auto",
        upload_preset:
          process.env.CLOUDINARY_UPLOAD_PRESET || "rombuzz_unsigned",
      }
    );

    if (!uploadRes || !uploadRes.secure_url) {
      return res
        .status(500)
        .json({ ok: false, error: "Cloudinary upload failed" });
    }

    console.log(`✅ Media uploaded by ${userId}: ${uploadRes.secure_url}`);
    res.json({ ok: true, url: uploadRes.secure_url });
  } catch (err) {
    console.error("❌ Upload failed:", err);
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ ok: false, error: "Expired token" });
    }
    res
      .status(500)
      .json({ ok: false, error: err.message || "Upload failed" });
  }
});
// ===================================================
// 📸 Story Upload Endpoint (24-hour visible Stories)
// ===================================================
app.post("/api/stories", authMiddleware, async (req, res) => {
  try {
    const { mediaUrl, text = "" } = req.body || {};
    if (!mediaUrl) {
      return res.status(400).json({ error: "mediaUrl required" });
    }

    await db.read();
    const me = req.user?.id;
    const user = db.data.users.find(u => u.id === me);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Create Story object
    const story = {
      id: shortid.generate(),
      userId: me,
      mediaUrl,
      text,
      type: /\.(mp4|mov|webm|ogg)$/i.test(mediaUrl) ? "video" : "image",
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24h lifespan
      isActive: true,
      views: [],
    };

    // Add to a new array in DB (separate from posts)
    db.data.stories ||= [];
    db.data.stories.push(story);
    await db.write();

    res.json({ success: true, story });
  } catch (e) {
    console.error("❌ Story upload failed:", e);
    res.status(500).json({ error: "failed to create story" });
  }
});
// =======================
// 📸 STORIES SYSTEM
// =======================
app.get("/api/stories", authMiddleware, async (req, res) => {
  await db.read();
  const all = db.data.stories || [];
  const active = all.filter(
    (s) => !s.expiresAt || s.expiresAt > Date.now()
  );
  const stories = active.map((s) => {
    const user = db.data.users.find((u) => u.id === s.userId);
    return { ...s, user };
  });
  res.json({ stories });
});

app.post("/api/stories", authMiddleware, upload.single("media"), async (req, res) => {
  try {
    await db.read();
    const me = req.user.id;
    const file = req.file;
    if (!file) return res.status(400).json({ error: "No media uploaded" });

    const uploadRes = await cloudinary.uploader.upload(file.path, {
      folder: "rombuzz_stories",
      resource_type: "auto",
    });
    fs.unlinkSync(file.path);

    const story = {
      id: shortid.generate(),
      userId: me,
      mediaUrl: uploadRes.secure_url,
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      isActive: true,
    };

    db.data.stories ||= [];
    db.data.stories.push(story);
    await db.write();

    res.json({ success: true, story });
  } catch (err) {
    console.error("Story upload failed:", err);
    res.status(500).json({ error: "Story creation failed" });
  }
});


// Delete expired stories (optional cleanup)
app.delete("/api/stories/cleanup", async (req, res) => {
  await db.read();
  db.data.stories = (db.data.stories || []).filter(
    (s) => s.expiresAt > Date.now()
  );
  await db.write();
  res.json({ cleaned: true });
});

// ===================================================
// 📖 Get all active Stories
// ===================================================
app.get("/api/stories", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const now = Date.now();
    const list = (db.data.stories || [])
      .filter(s => s.isActive !== false && s.expiresAt > now)
      .sort((a, b) => b.createdAt - a.createdAt);
    res.json({ stories: list });
  } catch (e) {
    console.error("❌ Stories fetch failed:", e);
    res.status(500).json({ error: "failed to load stories" });
  }
});


/* ======================
   USER PUBLIC PROFILE
====================== */

app.get("/api/users/:id", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const viewerId = req.user.id;
    const targetId = req.params.id;

    const target = db.data.users.find((u) => u.id === targetId);
    if (!target) return res.status(404).json({ error: "User not found" });

    // 🚫 Ensure array safety
    db.data.likes = db.data.likes || [];
    db.data.matches = db.data.matches || [];
    db.data.blocks = db.data.blocks || [];
    if (!Array.isArray(target.media)) target.media = [];
    if (!Array.isArray(target.posts)) target.posts = [];

    // 🚫 Block check
    const isBlocked =
      (db.data.blocks || []).some(
        (b) =>
          (b.blocker === viewerId && b.blocked === targetId) ||
          (b.blocker === targetId && b.blocked === viewerId)
      );

    if (isBlocked) {
      return res
        .status(403)
        .json({ error: "You are blocked or have blocked this user." });
    }

    // 💬 Relationship context
    const likedByMe = (db.data.likes || []).some(
      (l) => l.from === viewerId && l.to === targetId
    );
    const likedMe = (db.data.likes || []).some(
      (l) => l.from === targetId && l.to === viewerId
    );
    const matched = (db.data.matches || []).some((m) =>
  (Array.isArray(m.users) && m.users.includes(viewerId) && m.users.includes(targetId)) ||
  (m.a === viewerId && m.b === targetId) ||
  (m.a === targetId && m.b === viewerId)
);

    // If not self and not matched → return a limited preview (200)
if (viewerId !== targetId && !matched) {
  const preview = {
    id: target.id,
    firstName: target.firstName,
    lastName: (target.lastName ? target.lastName[0] : "") || "",
    avatar: target.avatar || "",
    bio: target.bio || "",
    vibe: target.vibe || "",
    gender: target.gender || "",
    verified: !!target.verified,
    visibilityMode: target.visibilityMode,
    fieldVisibility: target.fieldVisibility || {},
    media: (target.media || []).filter((m) => m.privacy !== "private").slice(0, 3),
    posts: [], // hide posts until matched
  };

  return res.json({
    user: preview,
    likedByMe,
    likedMe,
    matched: false,
    blocked: isBlocked,
  });
}

// Otherwise (self or matched) → full view
const safeUser = baseSanitizeUser(target);
safeUser.media = (target.media || []).filter((m) => m.privacy !== "private");
safeUser.posts = (target.posts || []).filter(
  (p) => p.visibility === "public" || (p.visibility === "matches" && matched)
);

return res.json({
  user: safeUser,
  likedByMe,
  likedMe,
  matched,
  blocked: isBlocked,
});

  } catch (err) {
    console.error("❌ Error in /api/users/:id:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/* ======================
   DISCOVER (Full Filters, Final)
====================== */
app.get("/api/discover", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const self = db.data.users.find((u) => u.id === req.user.id);
    // Requester context
const me = self;

// Normalize requested vibe
const requestedVibe = String(req.query.vibe || '').toLowerCase();

// If requested vibe is restricted, ensure eligibility; otherwise drop that filter
let canFilterWithRequestedVibe = true;
if (requestedVibe && isRestricted(requestedVibe) && !canUseRestricted(me)) {
  canFilterWithRequestedVibe = false;
}

    if (!self) return res.status(404).json({ error: "User not found" });

    // Query parameters (from frontend filters)
    const {
      lat,
      lng,
      range = 0, // meters
      gender,
      intent,
      vibe,
      interest,
      blur,
      online,
      verified,
      zodiac,
      love,
    } = req.query;

   // Determine coordinates (prefer request, then last known)
let baseLat = parseFloat(lat) || self.location?.lat;
let baseLng = parseFloat(lng) || self.location?.lng;

if (process.env.NODE_ENV === 'production') {
  // In production: require real coords
  if (!baseLat || !baseLng) {
    return res.status(400).json({
      error: "Missing coordinates. Please allow location access.",
    });
  }
} else {
  // In dev: fall back so you can test on desktops without GPS
  if (!baseLat || !baseLng) {
    baseLat = Number(process.env.DEV_DEFAULT_LAT || 41.8781);
    baseLng = Number(process.env.DEV_DEFAULT_LNG || -87.6298);
  }
}

// ✅ Update user’s last known location if changed or missing
if (!self.location || self.location.lat !== baseLat || self.location.lng !== baseLng) {
  self.location = { lat: baseLat, lng: baseLng };
  await db.write();
}


    const allUsers = db.data.users || [];
    const likedIds = (db.data.likes || [])
      .filter((l) => l.from === self.id)
      .map((l) => l.to);

    // Base filter: exclude self and people already liked, and hidden users
    let candidates = allUsers.filter(
      (u) => u.id !== self.id && !likedIds.includes(u.id) && u.visibility !== "invisible"
    );

    /* -----------------------------
       🩷 Tier 1 — Basic Filters
    ------------------------------*/
    if (gender)
      candidates = candidates.filter(
        (u) => (u.gender || "").toLowerCase() === gender.toLowerCase()
      );
    if (intent)
      candidates = candidates.filter(
        (u) => (u.intent || "").toLowerCase() === intent.toLowerCase()
      );

    // 🗺️ Distance filter (if provided)
    if (range > 0 && self.location?.lat && self.location?.lng) {
      const R = 6371e3; // meters
      candidates = candidates.filter((u) => {
        if (!u.location?.lat || !u.location?.lng) return false;
        const dLat = ((u.location.lat - baseLat) * Math.PI) / 180;
        const dLng = ((u.location.lng - baseLng) * Math.PI) / 180;
        const a =
          Math.sin(dLat / 2) ** 2 +
          Math.cos(baseLat * Math.PI / 180) *
            Math.cos(u.location.lat * Math.PI / 180) *
            Math.sin(dLng / 2) ** 2;
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c <= range;
      });
    }

    
    /* -----------------------------
   🧠 Tier 2 — Lifestyle Filters
------------------------------*/
if (vibe && canFilterWithRequestedVibe) {
  const v = requestedVibe;
  candidates = candidates.filter((u) => (u.vibe || "").toLowerCase() === v);
} else if (vibe && !canFilterWithRequestedVibe) {
  // silently ignore restricted filter if user isn't eligible
  // (optional) you could res.status(403) instead
}
   
    if (interest)
      candidates = candidates.filter((u) =>
        (u.interests || [])
          .map((x) => x.toLowerCase())
          .includes(interest.toLowerCase())
      );
    if (blur)
      candidates = candidates.filter((u) =>
        (u.favorites || []).includes(`blur:${blur}`)
      );
    if (online) {
      const now = Date.now();
      candidates = candidates.filter((u) => {
        const last = u.lastActive || 0;
        if (online === "active") return now - last < 5 * 60 * 1000;
        if (online === "recent") return now - last < 60 * 60 * 1000;
        return true;
      });
    }

    /* -----------------------------
       💎 Tier 3 — Premium Filters
    ------------------------------*/
    if (verified === "true") candidates = candidates.filter((u) => u.verified);
    if (zodiac)
      candidates = candidates.filter(
        (u) => (u.zodiac || "").toLowerCase() === zodiac.toLowerCase()
      );
    if (love)
      candidates = candidates.filter(
        (u) => (u.loveLanguage || "").toLowerCase() === love.toLowerCase()
      );

    /* -----------------------------
       ✨ Response Sanitization
    ------------------------------*/
    const sanitize = (u) => ({
      id: u.id,
      firstName: u.firstName,
      lastName: u.lastName,
      avatar: u.avatar || "https://via.placeholder.com/400x400?text=No+Photo",
      bio: u.bio || "",
      gender: u.gender || "",
      vibe: u.vibe || "",
      intent: u.intent || "",
      verified: u.verified || false,
      zodiac: u.zodiac || "",
      loveLanguage: u.loveLanguage || "",
      distanceMeters: u.location
        ? Math.round(getDistanceMeters(baseLat, baseLng, u.location.lat, u.location.lng))
        : null,
    });

    res.json({ users: candidates.map(sanitize) });
  } catch (err) {
    console.error("❌ DISCOVER ERROR:", err);
    res.status(500).json({ error: "Internal error in /discover" });
  }
});

/* -----------------------------
   Helper: Distance calculator
------------------------------*/
function getDistanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) *
      Math.cos(lat2 * Math.PI / 180) *
      Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/* ======================
   MESSAGES
====================== */
app.post('/api/messages', authMiddleware, async (req, res) => {
  await db.read();
 // 🧩 Accept text or media (photo/video) + ephemeral mode
const { to, text, type, url, ephemeral } = req.body || {};
if (!to) return res.status(400).json({ error: "recipient required" });

// validate message content
if (!text && !url) {
  return res.status(400).json({ error: "either text or media url required" });
}

// Block check
if (isBlocked(req.user.id, to))
  return res.status(403).json({ error: "blocked" });

// Recipient check
const exists = db.data.users.find((u) => u.id === to);
if (!exists) return res.status(400).json({ error: "recipient not found" });

// determine message type
const msgType = type || (url ? "photo" : "text");

// construct message
const msg = {
  id: shortid.generate(),
  from: req.user.id,
  to,
  text: text || "",
  type: msgType,
  url: url || null,
  ephemeral: ephemeral || "keep", // "once" or "keep"
  createdAt: Date.now(),
};

// Save message
db.data.messages.push(msg);
await db.write();


 // 📨 Notify receiver if online
const receiverSocket = onlineUsers[to];
if (receiverSocket) {
  io.to(receiverSocket).emit('message', msg);
  io.to(String(to)).emit('direct:message', {
    id: msg.id,
    roomId: [String(msg.from), String(msg.to)].sort().join('_'),
    from: msg.from,
    to: msg.to,
    time: new Date(msg.createdAt).toISOString?.() || new Date().toISOString(),
    preview: (msg.text || '').slice(0, 80),
    type: 'text',
  });
}

// ✅ Notify sender for delivery confirmation
const senderSocket = onlineUsers[req.user.id];
if (senderSocket) {
  io.to(senderSocket).emit('message:delivered', {
    id: msg.id,
    to: msg.to,
    time: msg.createdAt,
  });
}


  res.json({ message: msg });
});

app.get('/api/messages', authMiddleware, async (req, res) => {
  await db.read();
  const { user1, user2 } = req.query;
  if (!user1 || !user2) return res.status(400).json({ error: 'user1 & user2 required' });
  if (![user1, user2].includes(req.user.id)) return res.status(403).json({ error: 'forbidden' });

  if (isBlocked(user1, user2)) return res.status(403).json({ error: 'blocked' });

 // ✅ Build conversation between two users
const me = user1;
const other = user2;

// fetch messages where (from===me && to===other) or vice versa
const convo =
  db.data.messages?.filter(
    (m) =>
      (m.from === me && m.to === other) ||
      (m.from === other && m.to === me)
  ) || [];

// if no messages, only allow if users are matched
if (convo.length === 0) {
  const matched = db.data.matches?.some(
    (m) =>
      (m.a === me && m.b === other) || (m.a === other && m.b === me)
  );
  if (matched) {
    return res.json({ messages: [] });
  } else {
    return res.status(403).json({ error: "No match yet" });
  }
}

// ✅ Include all fields (text, type, url, ephemeral, timestamps)
res.json({
  messages: convo.map((m) => ({
    id: m.id,
    from: m.from,
    to: m.to,
    text: m.text || "",
    type: m.type || "text",
    url: m.url || null,
    ephemeral: m.ephemeral || "keep",
    createdAt: m.createdAt || Date.now(),
  })),
});
});
/* ======================
   AUTO-DELETE VIEW-ONCE MESSAGES
====================== */
app.post("/api/messages/viewed", authMiddleware, async (req, res) => {
  try {
    const { messageId } = req.body || {};
    if (!messageId) return res.status(400).json({ error: "messageId required" });

    await db.read();

    const msgIndex = db.data.messages.findIndex((m) => m.id === messageId);
    if (msgIndex === -1) return res.status(404).json({ error: "Message not found" });

    const msg = db.data.messages[msgIndex];

    // Only delete if ephemeral === "once"
    if (msg.ephemeral === "once") {
      db.data.messages.splice(msgIndex, 1);
      await db.write();

      console.log(`🗑️ View-once message deleted: ${messageId}`);

      // Optional: Notify both users that the message vanished
      const socketTo = onlineUsers[msg.to];
      const socketFrom = onlineUsers[msg.from];
      if (socketTo) io.to(socketTo).emit("message:removed", { id: messageId });
      if (socketFrom) io.to(socketFrom).emit("message:removed", { id: messageId });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Auto-delete error:", err);
    res.status(500).json({ error: "server error" });
  }
});



/* ======================
   LIKES & MATCHES
====================== */
app.post("/api/likes", authMiddleware, async (req, res) => {
  if (!ENABLE_LIKES_MATCHES)
    return res.status(403).json({ error: "likes disabled" });
  await db.read();

  const { to } = req.body;
  if (!to) return res.status(400).json({ error: "to required" });

  if (isBlocked(req.user.id, to))
    return res.status(403).json({ error: "blocked" });

  const alreadyLiked = db.data.likes.find(
    (l) => l.from === req.user.id && l.to === to
  );
  if (alreadyLiked)
    return res.status(400).json({ error: "already liked" });

  const self = db.data.users.find((u) => u.id === req.user.id);
  db.data.likes.push({ from: req.user.id, to, createdAt: Date.now() });

  const mutual = db.data.likes.find(
    (l) => l.from === to && l.to === req.user.id
  );
  if (mutual) {
    const existsMatch = db.data.matches.some(
      (m) => m.users.includes(req.user.id) && m.users.includes(to)
      
    );

    if (!existsMatch) {
      db.data.matches.push({ users: [req.user.id, to], createdAt: Date.now() });
    }
  }
  await db.write();

  const targetSocket = onlineUsers[to];

  if (mutual) {
    // 🎉 Both liked each other → send match event to both
    const selfSocket = onlineUsers[req.user.id];
    if (selfSocket) io.to(selfSocket).emit("match", { otherUserId: to });
    if (targetSocket)
      io.to(targetSocket).emit("match", { otherUserId: req.user.id });

    // ✅ Send MATCH notification to both users
   const fromName = self?.firstName || "Someone";
const other = (db.data.users || []).find(u => u.id === to);
const otherName = other?.firstName || "Someone";

// Tell THEM it’s a match with ME (fromName)
await sendNotification(to, {
  fromId: req.user.id,
  type: "buzz",
  message: `${fromName} wants to match with you! 💖`,
  href: `/viewProfile/${req.user.id}`,
});


// Tell ME it’s a match with THEM (otherName)
await sendNotification(req.user.id, {
  fromId: to,
  type: "match",
  message: `💞 It's a match with ${otherName}!`,
  href: `/viewProfile/${to}`, // ✅ Direct link to matched user
});

  } else {
    // 💌 First buzz → send buzz_request popup to target
    if (targetSocket) {
      const fromUser = baseSanitizeUser(self);

      // ✅ Log first for debugging
      console.log("📨 Buzz request sent →", {
        from: req.user.id,
        to,
        name: fromUser.firstName || "Someone nearby",
        selfieUrl: fromUser.avatar || "",
        targetSocket,
      });

      // ✅ Emit buzz popup
      io.to(targetSocket).emit("buzz_request", {
        fromId: req.user.id,
        name: fromUser.firstName || "Someone nearby",
        selfieUrl: fromUser.avatar || "",
      });
    } else {
      console.log(
        `⚠️ No active socket for user ${to}, buzz_request not sent.`
      );
    }

   // ✅ Send MATCH REQUEST notification
const fromName = self?.firstName || "Someone nearby";
await sendNotification(to, {
  fromId: req.user.id,
  type: "buzz", 
  message: `${fromName} wants to match with you! 💖`,
});
  }

  // ✅ Always respond to client at the end
  res.json({ success: true, matched: !!mutual });
});

// ======================
// BUZZ BETWEEN MATCHED USERS - WITH MATCHSTREAK
// ======================
app.post("/api/buzz", authMiddleware, async (req, res) => {
  const fromId = req.user.id;
  const { to } = req.body || {};
  if (!to) return res.status(400).json({ error: "to required" });

  // Use sorted pair so A↔B share one lock & cooldown entry
  const pairKey = [String(fromId), String(to)].sort().join("_");

  // Serialize concurrent buzzes for this pair (prevents +2 races)
  if (buzzLocks.has(pairKey)) {
    return res.status(429).json({ error: "busy" });
  }
  buzzLocks.add(pairKey);

  try {
    await db.read();
    const data = db.data;
    if (!data) return res.status(500).json({ error: "Database error" });

    // Ensure collections
    data.matches       = data.matches || [];
    data.users         = data.users || [];
    data.blocks        = data.blocks || [];
    data._buzzCooldown = data._buzzCooldown || {};
    data.matchStreaks  = data.matchStreaks || {};

    // Block check
    if (isBlocked(fromId, to)) {
      return res.status(403).json({ error: "blocked" });
    }

    // Require match
    const matched = data.matches.some(
      (m) => Array.isArray(m.users) && m.users.includes(fromId) && m.users.includes(to)
    );
    if (!matched) {
      return res.status(409).json({ error: "not_matched" });
    }

    // Cooldown per sorted pair
    const now = Date.now();
    const COOLDOWN_MS = 10 * 1000;
    const last = data._buzzCooldown[pairKey] || 0;
    if (now - last < COOLDOWN_MS) {
      return res.status(429).json({
        error: "cooldown",
        retryInMs: COOLDOWN_MS - (now - last),
      });
    }
    data._buzzCooldown[pairKey] = now;

   // ✅ Increment directed streak: only fromId -> to
const streakObj = incMatchStreakOut(data, fromId, to);
const currentStreak = Number(streakObj.count || 0);

    await db.write();

    // Notify (best-effort)
    const sender = data.users.find((u) => u.id === fromId);
    const fromName = sender?.firstName || "Someone";
    let message = `${fromName} buzzed you! Buzz them back! 💖`;
    if (currentStreak > 1) message += `\n🔥 MatchStreak: ${currentStreak}`;
    else if (currentStreak === 1) message += `\n🎉 Start a MatchStreak!`;

    try {
      await sendNotification(to, {
  fromId,
  type: "buzz",
  message,
  href: `/viewProfile/${fromId}`,
  streak: currentStreak,
});

    } catch (notifErr) {
      console.error("Notification error (ignored):", notifErr);
    }

    console.log(`✅ Buzz OK. Streak now ${currentStreak}`);
    return res.json({ success: true, streak: currentStreak });
  } catch (e) {
    console.error("❌ Buzz endpoint error:", e);
    return res.status(500).json({ error: "internal_error" });
  } finally {
    buzzLocks.delete(pairKey);
  }
});



// --- Like status ---
app.get('/api/likes/status/:targetUserId', authMiddleware, async (req, res) => {
  await db.read();
  const targetId = req.params.targetUserId;
  const selfId = req.user.id;

  const targetUser = db.data.users.find(u => u.id === targetId);
  if (!targetUser) return res.status(404).json({ error: 'target user not found' });

  const likedByMe = db.data.likes.some(l => l.from === selfId && l.to === targetId);
  const likedMe = db.data.likes.some(l => l.from === targetId && l.to === selfId);
  const matched = db.data.matches.some(m => m.users.includes(selfId) && m.users.includes(targetId));

  res.json({ likedByMe, likedMe, matched });
});


// --- Matches list ---
app.get('/api/matches', authMiddleware, async (req, res) => {
  await db.read();
  const selfId = req.user.id;
  const matches = db.data.matches
    .filter((m) => m.users.includes(selfId))
    .map((m) => {
      const otherId = m.users.find((id) => id !== selfId);
      const u = db.data.users.find((x) => x.id === otherId);
      if (!u) return null;
      return {
        id: u.id,
        firstName: u.firstName,
        lastName: u.lastName,
        avatar: u.avatar || "https://via.placeholder.com/150x150?text=No+Photo",
        bio: u.bio || "",
        gender: u.gender || "",
        verified: u.verified || false,
      };
    })
    .filter(Boolean);
  res.json(matches);
});
// ======================
// GET MATCHSTREAK BETWEEN USERS
// ======================
app.get("/api/matchstreak/:otherUserId", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const myId = String(req.user.id);
    const otherId = String(req.params.otherUserId);

    if (!db.data.matchStreaks) db.data.matchStreaks = {};
    const k = `${myId}_${otherId}`; // 🔁 NO SORT — directed (me -> other)
    const s = db.data.matchStreaks[k];

    const payload = s ? {
      from: s.from,
      to: s.to,
      count: Number(s.count || 0),
      lastBuzz: s.lastBuzz || null,
      createdAt: s.createdAt || null,
    } : {
      from: myId,
      to: otherId,
      count: 0,
      lastBuzz: null,
      createdAt: null,
    };

    console.log("📊 GET /matchstreak", { key: k, myId, otherId, count: payload.count });
    return res.json({ streak: payload });
  } catch (e) {
    console.error("MatchStreak error:", e);
    res.status(500).json({ error: "internal_error" });
  }
});


// --- Unmatch a user ---
app.post('/api/unmatch/:id', authMiddleware, async (req, res) => {
  try {
    await db.read();
    const me   = req.user.id;
    const them = req.params.id;

    // remove the match record
    const before = (db.data.matches || []).length;
    db.data.matches = (db.data.matches || []).filter(
      (m) => !(Array.isArray(m.users) && m.users.includes(me) && m.users.includes(them))
    );

    // (optional) also clear mutual likes so they don't instantly rematch
    db.data.likes = (db.data.likes || []).filter(
      (l) => !((l.from === me && l.to === them) || (l.from === them && l.to === me))
    );

    await db.write();
    const removed = before !== db.data.matches.length;
    return res.json({ ok: true, unmatched: removed });
  } catch (e) {
    console.error('Unmatch error:', e);
    return res.status(500).json({ error: 'Could not unmatch' });
  }
});


// --- Social Stats: liked, liked you, matches ---
app.get('/api/social-stats', authMiddleware, async (req, res) => {
  await db.read();
  const userId = req.user.id;
  // Ensure arrays and types are consistent
db.data.likes   ||= [];
db.data.matches ||= [];
db.data.users   ||= [];

// Coerce all ids to strings for consistent comparison
const myId = String(userId);

  const users = db.data.users || [];
  const likes = db.data.likes || [];
  const matches = db.data.matches || [];

  const liked = likes.filter(l => l.from === userId).map(l => l.to);
  const likedYou = likes.filter(l => l.to === userId).map(l => l.from);
  const matched = matches.filter(m => m.users.includes(userId));

  res.json({
    likedCount: liked.length,
    likedYouCount: likedYou.length,
    matchCount: matched.length,
  });
});

// --- Social Lists: liked / likedYou / matches ---
app.get('/api/social/:type', authMiddleware, async (req, res) => {
  await db.read();
  const userId  = req.user.id;
  const users   = db.data.users   || [];
  const likes   = db.data.likes   || [];
  const matches = db.data.matches || [];
  const type    = req.params.type;

  let targetIds = [];

  // Normalize for both from/to and fromId/toId schemas
  const getFrom = (l) => l.from || l.fromId;
  const getTo   = (l) => l.to   || l.toId;

  if (type === "liked") {
    targetIds = likes.filter(l => getFrom(l) === userId).map(l => getTo(l));
  } else if (type === "likedYou") {
    targetIds = likes.filter(l => getTo(l) === userId).map(l => getFrom(l));
  } else if (type === "matches") {
    targetIds = matches
      .filter(m => Array.isArray(m.users) ? m.users.includes(userId)
                                          : String(m.userA) === userId || String(m.userB) === userId)
      .map(m => {
        if (Array.isArray(m.users)) return m.users.find(id => id !== userId);
        return m.userA === userId ? m.userB : m.userA;
      });
  } else {
    return res.status(400).json({ error: "Invalid type" });
  }

  // Deduplicate and map to safe profiles
  const idSet = new Set(targetIds);
  const result = users
    .filter(u => idSet.has(u.id))
    .map(u => ({
      id: u.id,
      firstName: u.firstName || "",
      lastName: u.lastName  || "",
      avatar: u.avatar || "https://via.placeholder.com/150x150?text=No+Photo",
      bio: u.bio || "",
      gender: u.gender || "",
      verified: !!u.verified,
    }));

  res.json(result);
});


/* ======================
   REPORT / BLOCK (Upgraded)
====================== */
app.post('/api/block', authMiddleware, async (req, res) => {
  const { targetId } = req.body || {};
  if (!targetId) return res.status(400).json({ error: 'targetId required' });
  await db.read();
  const exists = db.data.blocks.find(b => b.blocker === req.user.id && b.blocked === targetId);
  if (!exists) {
    db.data.blocks.push({ id: shortid.generate(), blocker: req.user.id, blocked: targetId, createdAt: Date.now() });
    await db.write();
  }
  res.json({ success: true });
});

app.post('/api/unblock', authMiddleware, async (req, res) => {
  const { targetId } = req.body || {};
  if (!targetId) return res.status(400).json({ error: 'targetId required' });
  await db.read();
  const before = db.data.blocks.length;
  db.data.blocks = db.data.blocks.filter(b => !(b.blocker === req.user.id && b.blocked === targetId));
  const changed = before !== db.data.blocks.length;
  await db.write();
  res.json({ success: true, changed });
});

app.get('/api/blocks', authMiddleware, async (req, res) => {
  await db.read();
  const myId = req.user.id;
  const list = db.data.blocks
    .filter(b => b.blocker === myId)
    .map(b => {
      const other = db.data.users.find(u => u.id === b.blocked);
      return { ...b, user: other ? baseSanitizeUser(other) : null };
    });
  res.json({ blocks: list });
});

app.post('/api/report', authMiddleware, async (req, res) => {
  const { targetId, reason } = req.body || {};
  if (!targetId || !reason) return res.status(400).json({ error: 'targetId & reason required' });
  await db.read();
  const rep = { id: shortid.generate(), from: req.user.id, targetId, reason, createdAt: Date.now(), status: 'open' };
  db.data.reports.push(rep);
  await db.write();
  res.json({ success: true, report: rep });
});

// Admin/moderation list (only ADMIN_EMAIL can view all; users can view their own submissions)
app.get('/api/reports', authMiddleware, async (req, res) => {
  await db.read();
  const myEmail = db.data.users.find(u => u.id === req.user.id)?.email || '';
  const isAdmin = ADMIN_EMAIL && ADMIN_EMAIL.toLowerCase() === myEmail.toLowerCase();
  const ownOnly = !isAdmin || !('all' in req.query);

  let reports = db.data.reports;
  if (ownOnly) reports = reports.filter(r => r.from === req.user.id);

  const decorated = reports.map(r => {
    const fromU = db.data.users.find(u => u.id === r.from);
    const tgtU = db.data.users.find(u => u.id === r.targetId);
    return {
      ...r,
      fromUser: fromU ? baseSanitizeUser(fromU) : null,
      targetUser: tgtU ? baseSanitizeUser(tgtU) : null
    };
  });

  res.json({ reports: decorated, admin: isAdmin });
});

/* ======================
   AI WINGMAN (Mock or Real)
====================== */
async function callOpenAI(prompt, system) {
  if (!ENABLE_AI_WINGMAN || !process.env.OPENAI_API_KEY) {
    const err = new Error('AI disabled');
    err.code = 'AI_DISABLED';
    throw err;
  }
  if (typeof fetch !== 'function') {
    const err = new Error('fetch not available in this Node environment');
    err.code = 'NO_FETCH';
    throw err;
  }

  const body = {
    model: 'gpt-4o-mini',
    messages: [
      system ? { role: 'system', content: system } : null,
      { role: 'user', content: prompt }
    ].filter(Boolean),
    temperature: 0.7
  };

  const resp = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`OpenAI error: ${resp.status} ${t}`);
  }
  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() || '';
}

app.post('/api/ai/wingman/suggest', authMiddleware, async (req, res) => {
  const { myProfileSummary = '', theirProfileSummary = '', style = 'friendly' } = req.body || {};
  try {
    if (!ENABLE_AI_WINGMAN || !process.env.OPENAI_API_KEY) {
      // Mock suggestions (no key needed)
      const examples = {
        funny: [
          "Are you made of copper and tellurium? Because you're Cu-Te 😄",
          "I was today years old when I realized I should message you.",
          "Quick question—coffee or chaotic first date?"
        ],
        polite: [
          "Hi! I really liked your profile—it feels warm and genuine.",
          "Hey there! How’s your day going?",
          "I’d love to know what makes you smile the most."
        ],
        flirty: [
          "I was going to wait… but you seem worth breaking the ice for 😉",
          "Your smile might be my new favorite notification.",
          "Is it me, or did the room just get warmer?"
        ],
        casual: [
          "Hey, what’s up?",
          "How’s your week going?",
          "You seem cool—what kind of music are you into?"
        ],
        friendly: [
          "Hey! You seem like someone fun to talk to 😊",
          "Hi! What’s one thing that always makes you laugh?",
          "I liked your vibe-mind if we chat?"
        ]
      };
      return res.json({ suggestions: examples[style] || examples.friendly });
    }

    const system = `You are an empathetic dating wingman. Provide 3 short openers tailored to the other person's profile. Style=${style}.`;
    const prompt = `My profile: ${myProfileSummary}\nTheir profile: ${theirProfileSummary}\nGive 3 different one-liner openers. Number them.`;
    const text = await callOpenAI(prompt, system);
    const suggestions = text.split(/\n+/).map(s => s.replace(/^\d+[\).\s-]?\s*/, '')).filter(Boolean).slice(0, 3);
    res.json({ suggestions: suggestions.length ? suggestions : [text] });
  } catch (e) {
    if (e.code === 'AI_DISABLED') return res.status(503).json({ error: 'AI disabled' });
    console.error(e);
    res.status(500).json({ error: 'AI error' });
  }
});

app.post('/api/ai/wingman/rewrite', authMiddleware, async (req, res) => {
  const { text = '', tone = 'friendly' } = req.body || {};
  try {
    if (!ENABLE_AI_WINGMAN || !process.env.OPENAI_API_KEY) {
      const mock = {
        friendly: `Friendly and open-minded person who loves meaningful conversations and cozy evenings ✨`,
        confident: `Confident, curious, and ready to explore new connections 💫`,
        funny: `Professional overthinker who still believes in good coffee and bad jokes ☕😂`,
        poetic: `A heart full of sunsets, words, and wonder 🌅`,
      };
      return res.json({ rewrite: mock[tone] || mock.friendly });
    }

    const system = `Rewrite messages for dating chat. Keep it short, warm, and natural. Tone=${tone}.`;
    const prompt = `Rewrite this, same intent, improved tone:\n"${text}"`;
    const out = await callOpenAI(prompt, system);
    res.json({ rewrite: out });
  } catch (e) {
    if (e.code === 'AI_DISABLED') return res.status(503).json({ error: 'AI disabled' });
    console.error(e);
    res.status(500).json({ error: 'AI error' });
  }
});
/* ======================
   PREMIUM / VERIFICATION
====================== */

// Get premium / KYC / consent status
app.get('/api/premium/status', authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json({
    premiumTier: u.premiumTier || "free",
    kycStatus: u.kycStatus || "unverified",
    consent: u.consent || { restrictedAccepted: false, at: 0, textHash: "" }
  });
});

// Accept restricted-area consent (record agreement)
app.post('/api/premium/consent', authMiddleware, async (req, res) => {
  const { textHash = "terms-restricted-v1" } = req.body || {};
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  u.consent = { restrictedAccepted: true, at: Date.now(), textHash };
  await db.write();
  res.json({ ok: true, consent: u.consent });
});

// DEV-ONLY: mock upgrade to premium (replace with billing later)
app.post('/api/premium/upgrade', authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  u.premiumTier = "plus";
  await db.write();
  res.json({ ok: true, premiumTier: u.premiumTier });
});

// DEV-ONLY: mock KYC pass (replace with provider webhook later)
// Helpers
function calcAgeFromDob(dobStr) {
  const d = new Date(dobStr);
  if (Number.isNaN(d.getTime())) return -1;
  const today = new Date();
  let age = today.getFullYear() - d.getFullYear();
  const m = today.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < d.getDate())) age--;
  return age;
}

/**
 * Upload ID metadata (store URL + DOB)
 * Body: { idUrl: string, dob: 'YYYY-MM-DD' }
 */
app.post('/api/premium/verify/upload-id', authMiddleware, async (req, res) => {
  const { idUrl = "", dob = "" } = req.body || {};
  if (!idUrl || !dob) return res.status(400).json({ error: 'idUrl and dob required' });
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });

  u.kyc = u.kyc || {};
  u.kyc.idUrl = idUrl;
  u.kyc.dob = dob;
  u.kyc.submittedAt = Date.now();
  u.kycStatus = "submitted"; // pending selfie + review
  await db.write();
  return res.json({ ok: true, kycStatus: u.kycStatus, kyc: { idUrl, dob } });
});

/**
 * Upload live selfie proof (store URL)
 * Body: { selfieUrl: string }
 */
app.post('/api/premium/verify/upload-selfie', authMiddleware, async (req, res) => {
  const { selfieUrl = "" } = req.body || {};
  if (!selfieUrl) return res.status(400).json({ error: 'selfieUrl required' });
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });

  u.kyc = u.kyc || {};
  u.kyc.selfieUrl = selfieUrl;
  u.kyc.selfieAt = Date.now();
  if (u.kycStatus === "unverified") u.kycStatus = "submitted";
  await db.write();
  return res.json({ ok: true, kycStatus: u.kycStatus, kyc: { selfieUrl } });
});

/**
 * Auto-approve when both documents exist and DOB >= 18
 * (dev convenience; replace with real provider callbacks later)
 */
app.post('/api/premium/verify/auto-approve', authMiddleware, async (req, res) => {
  await db.read();
  const u = db.data.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'not found' });

  const dob = u?.kyc?.dob;
  const idUrl = u?.kyc?.idUrl;
  const selfieUrl = u?.kyc?.selfieUrl;

  if (!dob || !idUrl || !selfieUrl) {
    return res.status(400).json({ error: 'missing_documents', require: { dob: !!dob, idUrl: !!idUrl, selfieUrl: !!selfieUrl } });
  }

  const age = calcAgeFromDob(dob);
  if (age < 0) return res.status(400).json({ error: 'invalid_dob' });
  if (age < 18) {
    u.kycStatus = "rejected_minor";
    await db.write();
    return res.status(403).json({ error: 'underage', age, kycStatus: u.kycStatus });
  }

  u.kycStatus = "verified";
  await db.write();
  return res.json({ ok: true, kycStatus: u.kycStatus, age });
});


/* ======================
   SAFE MEET CHECK-IN & CHAT ROOMS
====================== */
const fetch = require("node-fetch"); // safe if already imported; duplicate is fine

/* ======================
   CHAT ROOMS (PERSISTED)
====================== */

// Helper to get/create a room record
async function getRoomDoc(roomId) {
  await db.read();
  if (!db.data.roomMessages) db.data.roomMessages = [];
  let doc = db.data.roomMessages.find((r) => r.roomId === roomId);
  if (!doc) {
    doc = { roomId, list: [] };
    db.data.roomMessages.push(doc);
    await db.write();
  }
  return doc;
}

// Parse participants from "<a>_<b>"
function getPeersFromRoomId(roomId) {
  const [a, b] = String(roomId).split("_");
  return { a, b };
}

// ============================
// 💬 GET CHAT ROOM MESSAGES
// ============================
app.get("/api/chat/rooms/:roomId", authMiddleware, async (req, res) => {
  const { roomId } = req.params;
  const userId = req.user.id;

  await db.read();
  if (!Array.isArray(db.data.messages)) db.data.messages = [];

  const list = db.data.messages.filter((m) => m.roomId === roomId);

  // 🔥 Auto-delete ephemeral messages if viewed once
  const keep = [];
  const remove = [];
  for (const msg of list) {
    if (msg.ephemeral?.mode === "once") {
      // if viewer ≠ sender, delete immediately after serving
      if (msg.from !== userId) {
        remove.push(msg.id);
      } else {
        keep.push(msg); // sender still sees “sent once” note
      }
    } else {
      keep.push(msg);
    }
  }

  if (remove.length) {
    db.data.messages = db.data.messages.filter((m) => !remove.includes(m.id));
    await db.write();
  }

  res.json(keep);
});


// POST text or serialized media (::RBZ::...) into a room
app.post("/api/chat/rooms/:roomId", authMiddleware, async (req, res) => {
  const { roomId } = req.params;
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: "text required" });

  const { a, b } = getPeersFromRoomId(roomId);
  if (![a, b].includes(req.user.id))
    return res.status(403).json({ error: "forbidden" });

  // Block check (either direction)
  if (isBlocked(a, b)) {
    return res.status(403).json({ error: "blocked" });
  }

  const fromId = req.user.id;
  const toId = fromId === a ? b : a;

  const msg = {
    id: shortid.generate(),
    roomId,
    from: fromId,
    to: toId,
    text,
    type: text.startsWith("::RBZ::") ? "media" : "text",
    time: new Date().toISOString(),
    edited: false,
    deleted: false,
    reactions: {},
    hiddenFor: [],
  };

    // persist into correct collection
  const doc = await getRoomDoc(roomId);
  doc.list.push(msg);
  await db.write();

  // emit realtime to room
  io.to(roomId).emit("message", msg);

// 🔔 ping recipient's private room (navbar)
try {
  io.to(String(toId)).emit("direct:message", {
    id: msg.id,
    roomId,
    from: fromId,
    to: toId,
    time: msg.time,
    preview: (msg.text || "").slice(0, 80),
    type: msg.type || "text",
  });

  // ✅ and also their live socket id if present
  const sid = onlineUsers[toId];
  if (sid) {
    io.to(sid).emit("direct:message", {
      id: msg.id,
      roomId,
      from: fromId,
      to: toId,
      time: msg.time,
      preview: (msg.text || "").slice(0, 80),
      type: msg.type || "text",
    });
  }
} catch (e) {
  console.warn("direct:message emit failed (ignored):", e?.message || e);
}


  return res.json({ message: msg });

});

/* ======================
   MESSAGE ACTIONS (edit / delete / react)
====================== */

// Edit (sender only, within 1h)
app.patch('/api/chat/rooms/:roomId/:msgId', authMiddleware, async (req, res) => {
  const { roomId, msgId } = req.params;
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'text required' });

  const doc = await getRoomDoc(roomId);
  const msg = (doc.list || []).find(m => m.id === msgId);
  if (!msg) return res.status(404).json({ error: 'not found' });

  if (msg.from !== req.user.id) return res.status(403).json({ error: 'not owner' });

  const oneHour = 60 * 60 * 1000;
  if (Date.now() - new Date(msg.time).getTime() > oneHour)
    return res.status(400).json({ error: 'edit window expired' });

  msg.text = text;
  msg.edited = true;
  await db.write();

  io.to(roomId).emit('message:edit', { msgId, text });
  res.json({ ok: true });
});

// Unsend
// scope=me -> hide only for me; scope=all -> delete for everyone (owner only)
app.delete('/api/chat/rooms/:roomId/:msgId', authMiddleware, async (req, res) => {
  const { roomId, msgId } = req.params;
  const { scope = 'me' } = req.query;

  const doc = await getRoomDoc(roomId);
  const msg = (doc.list || []).find(m => m.id === msgId);
  if (!msg) return res.status(404).json({ error: 'not found' });

  if (scope === 'me') {
    if (!msg.hiddenFor) msg.hiddenFor = [];
    if (!msg.hiddenFor.includes(req.user.id)) msg.hiddenFor.push(req.user.id);
    await db.write();
    return res.json({ ok: true });
  }

  if (scope === 'all') {
    if (msg.from !== req.user.id) return res.status(403).json({ error: 'not owner' });
    msg.deleted = true;
    msg.text = 'This message was unsent';
    await db.write();
    io.to(roomId).emit('message:delete', { msgId });
    return res.json({ ok: true });
  }

  res.status(400).json({ error: 'invalid scope' });
  // 🧹 Delete entire conversation for *me* (hide all messages for the requester)
app.delete('/api/chat/rooms/:roomId', authMiddleware, async (req, res) => {
  const { roomId } = req.params;
  const myId = req.user.id;

  const doc = await getRoomDoc(roomId);
  if (!doc || !Array.isArray(doc.list)) return res.json({ ok: true });

  let changed = false;
  for (const m of doc.list) {
    m.hiddenFor ||= [];
    if (!m.hiddenFor.includes(myId)) {
      m.hiddenFor.push(myId);
      changed = true;
    }
  }
  if (changed) await db.write();
  return res.json({ ok: true, hidden: true });
});

});

// React / unreact (toggle)
app.post('/api/chat/rooms/:roomId/:msgId/react', authMiddleware, async (req, res) => {
  const { roomId, msgId } = req.params;
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'emoji required' });

  const doc = await getRoomDoc(roomId);
  const msg = (doc.list || []).find(m => m.id === msgId);
  if (!msg) return res.status(404).json({ error: 'not found' });

  if (!msg.reactions) msg.reactions = {};
  if (msg.reactions[req.user.id] === emoji) {
    delete msg.reactions[req.user.id];
  } else {
    msg.reactions[req.user.id] = emoji;
  }
  await db.write();

  io.to(roomId).emit('message:react', { msgId, userId: req.user.id, emoji: msg.reactions[req.user.id] || null });
  res.json({ ok: true, reactions: msg.reactions });
});

/* ======================
   SAFE MEET CHECK-IN
====================== */

async function nearbyPlaces(lat, lng) {
  const qs = new URLSearchParams({
    location: `${lat},${lng}`,
    radius: "4000",
    type: "cafe",
    key: process.env.GOOGLE_MAPS_API_KEY,
  });
  const r = await fetch(
    `https://maps.googleapis.com/maps/api/place/nearbysearch/json?${qs}`
  );
  const j = await r.json();
  (j.results || []).forEach((p) => {
    if (p.place_id)
      p.google_url = `https://www.google.com/maps/place/?q=place_id:${p.place_id}`;
  });
  return j.results || [];
}

app.post("/api/meet-suggest", authMiddleware, async (req, res) => {
  try {
    // ✅ Use real coordinates from frontend (A + B)
    const { fromLat, fromLng, toLat, toLng } = req.body;

    // Fallback for safety if any field missing
    if (!fromLat || !fromLng || !toLat || !toLng) {
      return res.status(400).json({ error: "missing_coordinates" });
    }

    const mid = {
      lat: (parseFloat(fromLat) + parseFloat(toLat)) / 2,
      lng: (parseFloat(fromLng) + parseFloat(toLng)) / 2,
    };

    const places = await nearbyPlaces(mid.lat, mid.lng);
    res.json({ midpoint: mid, places });
  } catch (err) {
    console.error("❌ meet-suggest error:", err);
    res.status(500).json({ error: "places_failed" });
  }
});

// When one chooses a place → send to both chats as a system message

/* ======================
   ENHANCED LETSBUZZ POSTS SYSTEM
====================== */

// Enhanced Post Creation with all features
app.post("/api/buzz/posts", authMiddleware, async (req, res) => {
  try {
    const {
      text,
      mediaUrl,
      type = "text", // text, photo, reel, story
      privacy = "matches", // public, matches, specific
      expiresAt, // for stories
      sharedWith = [], // specific user IDs for privacy: specific
      tags = []
    } = req.body;

    await db.read();
    const user = db.data.users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    const post = {
      id: shortid.generate(),
      userId: req.user.id,
      text: (text || "").trim(),
      mediaUrl: mediaUrl || "",
      type,
      privacy,
      sharedWith,
      tags,
      expiresAt: type === "story" ? (expiresAt || Date.now() + 24 * 60 * 60 * 1000) : null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      reactions: {}, // { userId: "emoji" }
      comments: [],
      shares: [],
      bookmarks: [],
      viewCount: 0,
      isActive: true
    };

    if (!user.posts) user.posts = [];
    user.posts.unshift(post);
    await db.write();

    // Notify matches about new post
    const matches = (db.data.matches || [])
      .filter(m => m.users.includes(req.user.id))
      .map(m => m.users.find(id => id !== req.user.id));

    for (const matchId of matches) {
      if (privacy === "matches" || (privacy === "specific" && sharedWith.includes(matchId))) {
      await sendNotification(matchId, {
  fromId: req.user.id,
  type: "new_post",
  message: `${user.firstName} posted something new! 📝`,
href: `/buzz/post/${post.id}`,
  entity: "post",
  entityId: post.id,
  postId: post.id,
  postOwnerId: req.user.id,
});

      }
    }

    res.json({ success: true, post });
  } catch (error) {
    console.error("Create post error:", error);
    res.status(500).json({ error: "Failed to create post" });
  }
});

// Get enhanced feed with filters
app.get("/api/buzz/feed", authMiddleware, async (req, res) => {
  try {
    const {
      type, // filter by post type
      search, // search in text/tags
      sort = "newest", // newest, popular
      limit = 50,
      offset = 0
    } = req.query;

    await db.read();
    const myId = req.user.id;

   // Get my matches (support both {users:[a,b]} and {userA,userB})
const myMatches = (db.data.matches || [])
  .filter(m =>
    (Array.isArray(m.users) && m.users.includes(myId)) ||
    m.userA === myId ||
    m.userB === myId
  )
  .map(m => {
    if (Array.isArray(m.users)) return m.users.find(id => id !== myId);
    return m.userA === myId ? m.userB : m.userA;
  });

    // Get all visible posts
    let posts = [];
    const allUsers = db.data.users || [];

    for (const user of allUsers) {
      if (!user.posts || !Array.isArray(user.posts)) continue;
      
      for (const post of user.posts) {
        if (!post.isActive) continue;
        
        // Check if post is expired (for stories)
        if (post.expiresAt && post.expiresAt < Date.now()) {
          post.isActive = false;
          continue;
        }
        // Treat undefined as active (legacy posts)
if (post.isActive === false) continue;
        // Check visibility
        let isVisible = false;
        if (post.userId === myId) {
          isVisible = true; // Always see own posts
        } else if (post.privacy === "public") {
          isVisible = true;
        } else if (post.privacy === "matches" && myMatches.includes(post.userId)) {
          isVisible = true;
        } else if (post.privacy === "specific" && post.sharedWith.includes(myId)) {
          isVisible = true;
        }

        if (isVisible) {
          const postUser = baseSanitizeUser(user);
          posts.push({
            ...post,
            user: postUser,
            reactionCount: Object.keys(post.reactions || {}).length,
            commentCount: (post.comments || []).length,
            shareCount: (post.shares || []).length,
            hasBookmarked: (post.bookmarks || []).includes(myId),
            myReaction: post.reactions?.[myId] || null
          });
        }
      }
    }

    // Apply filters
    if (type && type !== "all") {
      posts = posts.filter(post => post.type === type);
    }

    if (search) {
      const searchLower = search.toLowerCase();
      posts = posts.filter(post => 
        post.text.toLowerCase().includes(searchLower) ||
        (post.tags || []).some(tag => tag.toLowerCase().includes(searchLower))
      );
    }

    // Apply sorting
    if (sort === "popular") {
      posts.sort((a, b) => {
        const aScore = a.reactionCount + a.commentCount * 2 + a.shareCount * 3;
        const bScore = b.reactionCount + b.commentCount * 2 + b.shareCount * 3;
        return bScore - aScore;
      });
    } else {
      posts.sort((a, b) => b.createdAt - a.createdAt);
    }

    // Pagination
    const paginatedPosts = posts.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    res.json({
      posts: paginatedPosts,
      total: posts.length,
      hasMore: parseInt(offset) + parseInt(limit) < posts.length
    });
  } catch (error) {
    console.error("Feed error:", error);
    res.status(500).json({ error: "Failed to load feed" });
  }
});
// Increment view counter for a post (used by Reels after ~3s)
app.post("/api/buzz/posts/:postId/view", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const { postId } = req.params;
    const users = db.data.users || [];

    // locate owner and post
    const owner = users.find(u => u.posts?.some(p => p.id === postId));
    if (!owner) return res.status(404).json({ error: "Post not found" });

    const post = owner.posts.find(p => p.id === postId);
    post.viewCount = Number(post.viewCount || 0) + 1;
    post.updatedAt = Date.now();
    await db.write();

    res.json({ ok: true, viewCount: post.viewCount });
  } catch (e) {
    console.error("viewCount error:", e);
    res.status(500).json({ error: "Failed to record view" });
  }
});

// Enhanced Reaction System
app.post("/api/buzz/posts/:postId/react", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { emoji } = req.body;
    const myId = req.user.id;

    if (!emoji) return res.status(400).json({ error: "Emoji required" });

    await db.read();
    
    // Find post owner
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (!post.reactions) post.reactions = {};

    const hadReaction = post.reactions[myId];
    post.reactions[myId] = emoji;
    post.updatedAt = Date.now();

    await db.write();
// Send notification if not own post and new reaction
if (post.userId !== myId && !hadReaction) {
  const reactor = db.data.users.find(u => u.id === myId);
  const reactorName = reactor ? reactor.firstName : "Someone";

  await sendNotification(post.userId, {
    fromId: myId,
    type: "reaction",
    message: `${reactorName} reacted with ${emoji} to your post`,
    href: `/buzz/post/${postId}`,
    entity: "post",
    entityId: postId,
    postId,
    postOwnerId: post.userId,
  });
}

    // Count reactions by emoji
    const reactionCounts = {};
    Object.values(post.reactions).forEach(emoji => {
      reactionCounts[emoji] = (reactionCounts[emoji] || 0) + 1;
    });

    res.json({
      success: true,
      myReaction: emoji,
      reactionCounts,
      totalReactions: Object.keys(post.reactions).length
    });
  } catch (error) {
    console.error("Reaction error:", error);
    res.status(500).json({ error: "Failed to react" });
  }
});

// Remove reaction
app.delete("/api/buzz/posts/:postId/react", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    await db.read();
    
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (post.reactions && post.reactions[myId]) {
      delete post.reactions[myId];
      post.updatedAt = Date.now();
      await db.write();
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Remove reaction error:", error);
    res.status(500).json({ error: "Failed to remove reaction" });
  }
});

// Enhanced Comment System (Private comments)
app.post("/api/buzz/posts/:postId/comments", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { text, parentId = null } = req.body || {};
    const myId = req.user.id;

    if (!text?.trim()) return res.status(400).json({ error: "Comment text required" });

    await db.read();

    const postOwner = db.data.users.find(user =>
      user.posts?.some(post => post.id === postId)
    );
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (!post.userId) post.userId = postOwner.id; // ✅ ensure post has owner id

    if (!post.comments) post.comments = [];

    const comment = {
      id: shortid.generate(),
      userId: myId,
      text: text.trim(),
      parentId: parentId || null,      // ✅ store parent for replies
      createdAt: Date.now(),
      updatedAt: Date.now(),
      // ✅ Add visibleTo array for private comments - only visible to post owner and commenter
      visibleTo: [post.userId, myId]
    };

    post.comments.push(comment);
    post.updatedAt = Date.now();
    await db.write();

        // Send notification only to post owner if it's not their own comment
        if (post.userId !== myId) {
          const commenter = db.data.users.find(u => u.id === myId);
          const commenterName = commenter?.firstName || "Someone";
          
          await sendNotification(post.userId, {
            fromId: myId,
            type: "comment", 
            message: `${commenterName} commented on your post: "${text.slice(0, 50)}${text.length > 50 ? "..." : ""}"`,
            href: `/buzz/post/${postId}`,
            entity: "post",
            entityId: postId,
            postId: postId,
            postOwnerId: post.userId,
            // ✅ Include visibility info in notification metadata
            metadata: {
              visibleTo: [post.userId, myId]
            }
          });
        }
// ✅ Real-time comment broadcast (only commenter + post owner)
try {
  const socketPayload = { postId, comment };
  if (io && io.to) {
    io.to(String(myId)).emit("comment:new", socketPayload);
    if (post.userId !== myId)
      io.to(String(post.userId)).emit("comment:new", socketPayload);
  }
} catch (err) {
  console.error("Socket comment broadcast error:", err);
}

    res.json({ success: true, comment });
  } catch (error) {
    console.error("Comment error:", error);
    res.status(500).json({ error: "Failed to add comment" });
  }
});



// =======================================================
// 💬 Enhanced GET Comments — tolerant postId matching with visibility filtering
// =======================================================
app.get("/api/buzz/posts/:postId/comments", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;
    await db.read();

    // Debug print to help trace mismatches
    console.log("💬 GET comments for:", postId);

    if (!Array.isArray(db.data.users)) {
      return res.status(500).json({ error: "Invalid database structure" });
    }

    // ✅ match post.id or post._id, string or number
    const postOwner = db.data.users.find((user) =>
      (user.posts || []).some(
        (post) =>
          String(post.id) === String(postId) ||
          String(post._id) === String(postId)
      )
    );

    if (!postOwner) {
      console.warn("⚠️ No postOwner found for postId:", postId);
      return res.status(404).json({ error: `Post not found (${postId})` });
    }

    const post = (postOwner.posts || []).find(
      (p) =>
        String(p.id) === String(postId) ||
        String(p._id) === String(postId)
    );
    if (!Array.isArray(post.comments)) post.comments = [];

    // ✅ FILTER COMMENTS: Check visibleTo array or fall back to legacy visibility rules
    const filteredComments = (post.comments || []).filter(comment => {
      // If comment has visibleTo array, check it
      if (Array.isArray(comment.visibleTo)) {
        return comment.visibleTo.includes(myId);
      }
      // Legacy fallback: visible to comment author and post owner
      return comment.userId === myId || post.userId === myId;
    });
const commentsWithAuthors = filteredComments.map((comment) => {
  const author = db.data.users.find((u) => u.id === comment.userId);

  // Count comment reactions
  const reactionCounts = {};
  Object.values(comment.reactions || {}).forEach(emoji => {
    reactionCounts[emoji] = (reactionCounts[emoji] || 0) + 1;
  });

  return {
    ...comment,
    author: author ? baseSanitizeUser(author) : { firstName: "Unknown", avatar: "" },
    myReaction: comment.reactions?.[myId] || null,
    reactionCounts,
    totalReactions: Object.keys(comment.reactions || {}).length,
  };
});


    res.json({ comments: commentsWithAuthors });
  } catch (err) {
    console.error("💥 Enhanced comments fetch error:", err);
    res.status(500).json({ error: "Failed to get comments" });
  }
});




// Edit a Buzz comment (author only)
app.patch("/api/buzz/posts/:postId/comments/:commentId", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { text } = req.body || {};
    if (!text?.trim()) return res.status(400).json({ error: "text required" });

    await db.read();

    // locate owner that has this post
    const postOwner = db.data.users.find(user =>
      user.posts?.some(p => p.id === postId)
    );
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (!post?.comments) return res.status(404).json({ error: "Comment list missing" });

    const comment = post.comments.find(c => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });
    if (comment.userId !== req.user.id) return res.status(403).json({ error: "Not your comment" });

    comment.text = text.trim();
    comment.updatedAt = Date.now();
    
    // Ensure visibleTo array is maintained
    if (!Array.isArray(comment.visibleTo)) {
      comment.visibleTo = [post.userId, comment.userId];
    }
    
    await db.write();

    return res.json({ success: true, comment });
  } catch (e) {
    console.error("Buzz comment edit error:", e);
    res.status(500).json({ error: "Failed to edit comment" });
  }
});

// Delete a Buzz comment (author only)
app.delete("/api/buzz/posts/:postId/comments/:commentId", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;

    await db.read();

    const postOwner = db.data.users.find(user =>
      user.posts?.some(p => p.id === postId)
    );
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (!post?.comments) return res.json({ success: true, removed: false });

    const target = post.comments.find(c => c.id === commentId);
    if (!target) return res.json({ success: true, removed: false });
    if (target.userId !== req.user.id) return res.status(403).json({ error: "Not your comment" });

    const before = post.comments.length;
    post.comments = post.comments.filter(c => c.id !== commentId);
    const removed = before !== post.comments.length;

    await db.write();
    return res.json({ success: true, removed });
  } catch (e) {
    console.error("Buzz comment delete error:", e);
    res.status(500).json({ error: "Failed to delete comment" });
  }
});

// =======================================================
// 💬 COMMENT REACTIONS ENDPOINTS
// =======================================================

// Add comment reaction
app.post("/api/buzz/posts/:postId/comments/:commentId/react", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { emoji = "❤️" } = req.body;
    const myId = req.user.id;

    await db.read();
    
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    const comment = post?.comments?.find(c => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    // Initialize reactions object if not exists
    if (!comment.reactions) comment.reactions = {};
    
    const hadReaction = comment.reactions[myId];
    comment.reactions[myId] = emoji;
    comment.updatedAt = Date.now();
    await db.write();

    // Send notification to comment author if not own reaction
    if (comment.userId !== myId && !hadReaction) {
      await sendNotification(comment.userId, {
        fromId: myId,
        type: "reaction",
        message: `reacted with ${emoji} to your comment`,
href: `/buzz/post/${postId}`,
        entity: "comment",
        entityId: commentId,
        postId: postId,
        postOwnerId: post.userId,
      });
    }

    // Count reactions
    const reactionCounts = {};
    Object.values(comment.reactions || {}).forEach(emoji => {
      reactionCounts[emoji] = (reactionCounts[emoji] || 0) + 1;
    });

    res.json({
      success: true,
      myReaction: emoji,
      reactionCounts,
      totalReactions: Object.keys(comment.reactions || {}).length
    });
  } catch (error) {
    console.error("Comment reaction error:", error);
    res.status(500).json({ error: "Failed to react to comment" });
  }
});

// Remove comment reaction
app.delete("/api/buzz/posts/:postId/comments/:commentId/react", authMiddleware, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const myId = req.user.id;

    await db.read();
    
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    const comment = post?.comments?.find(c => c.id === commentId);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    if (comment.reactions && comment.reactions[myId]) {
      delete comment.reactions[myId];
      comment.updatedAt = Date.now();
      await db.write();
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Remove comment reaction error:", error);
    res.status(500).json({ error: "Failed to remove reaction" });
  }
});

// Bookmark post
app.post("/api/buzz/posts/:postId/bookmark", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    await db.read();
    
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (!post.bookmarks) post.bookmarks = [];

    if (!post.bookmarks.includes(myId)) {
      post.bookmarks.push(myId);
      await db.write();
    }

    res.json({ success: true, bookmarked: true });
  } catch (error) {
    console.error("Bookmark error:", error);
    res.status(500).json({ error: "Failed to bookmark" });
  }
});

// Remove bookmark
app.delete("/api/buzz/posts/:postId/bookmark", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    await db.read();
    
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (post.bookmarks) {
      post.bookmarks = post.bookmarks.filter(id => id !== myId);
      await db.write();
    }

    res.json({ success: true, bookmarked: false });
  } catch (error) {
    console.error("Remove bookmark error:", error);
    res.status(500).json({ error: "Failed to remove bookmark" });
  }
});

// Share post with matches
app.post("/api/buzz/posts/:postId/share", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const { shareWith = [] } = req.body; // array of user IDs
    const myId = req.user.id;

    await db.read();
    
    const postOwner = db.data.users.find(user => 
      user.posts?.some(post => post.id === postId)
    );
    
    if (!postOwner) return res.status(404).json({ error: "Post not found" });

    const post = postOwner.posts.find(p => p.id === postId);
    if (!post.shares) post.shares = [];

    const newShares = shareWith.filter(userId => !post.shares.includes(userId));
    post.shares.push(...newShares.map(userId => ({ userId, sharedBy: myId, sharedAt: Date.now() })));
    
    post.updatedAt = Date.now();
    await db.write();

    // Notify shared users
    for (const userId of newShares) {
      await sendNotification(userId, {
        fromId: myId,
        type: "share",
        message: `shared a post with you`

        
      });
    }

    res.json({ success: true, shares: post.shares });
  } catch (error) {
    console.error("Share error:", error);
    res.status(500).json({ error: "Failed to share" });
  }
});

// Get user's bookmarked posts
app.get("/api/buzz/bookmarks", authMiddleware, async (req, res) => {
  try {
    await db.read();
    const myId = req.user.id;

    let bookmarkedPosts = [];
    const allUsers = db.data.users || [];

    for (const user of allUsers) {
      if (!user.posts) continue;
      
      for (const post of user.posts) {
        if (post.bookmarks?.includes(myId)) {
          const postUser = baseSanitizeUser(user);
          bookmarkedPosts.push({
            ...post,
            user: postUser,
            hasBookmarked: true
          });
        }
      }
    }

    bookmarkedPosts.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ posts: bookmarkedPosts });
  } catch (error) {
    console.error("Bookmarks error:", error);
    res.status(500).json({ error: "Failed to get bookmarks" });
  }
});

// Delete post
app.delete("/api/buzz/posts/:postId", authMiddleware, async (req, res) => {
  try {
    const { postId } = req.params;
    const myId = req.user.id;

    await db.read();
    
    const user = db.data.users.find(u => u.id === myId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const postIndex = user.posts?.findIndex(post => post.id === postId);
    if (postIndex === -1) return res.status(404).json({ error: "Post not found" });

    user.posts.splice(postIndex, 1);
    await db.write();

    res.json({ success: true });
  } catch (error) {
    console.error("Delete post error:", error);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

// =======================================================
// === Like / Unlike a post (double-tap or button)      ===
// =======================================================
app.post('/api/posts/:postId/like', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;

  // locate the post inside its owner
  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: 'post not found' });

  const post = owner.posts.find(p => p.id === postId);
  post.likes ||= [];

  // toggle like
  const already = post.likes.find(l => l.userId === me);
  if (already) {
    post.likes = post.likes.filter(l => l.userId !== me);
  } else {
    const meUser = db.data.users.find(u => u.id === me) || {};
    post.likes.push({
      userId: me,
      name: `${meUser.firstName || ''} ${meUser.lastName || ''}`.trim(),
      avatar: meUser.avatar || '',
      createdAt: Date.now(),
    });
  }

  await db.write();
  res.json({ success: true, likesCount: post.likes.length });
});


// =======================================================
// 💬 BUZZ COMMENTS (used by LetsBuzz.jsx & BuzzPost.jsx)
// =======================================================

/* Get all comments for a buzz post
app.get("/api/buzz/posts/:postId/comments", authMiddleware, async (req, res) => {
  await db.read();
  const { postId } = req.params;
  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: "post not found" });

  const post = owner.posts.find(p => p.id === postId);
  post.comments ||= [];
  res.json({ comments: post.comments });
});

// Add a new comment to a buzz post
app.post("/api/buzz/posts/:postId/comments", authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;
  const { text, parentId } = req.body || {};
  if (!text?.trim()) return res.status(400).json({ error: "text required" });

  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: "post not found" });

  const post = owner.posts.find(p => p.id === postId);
  post.comments ||= [];

  const comment = {
    id: shortid.generate(),
    userId: me,
    text: text.trim(),
    parentId: parentId || null,
    createdAt: Date.now(),
  };
  post.comments.push(comment);
  await db.write();
// ✅ Real-time comment broadcast (only for commenter + post owner)
try {
  const socketPayload = { postId, comment };
  if (io && io.to) {
    io.to(String(me)).emit("comment:new", socketPayload);
    if (owner.id !== me) io.to(String(owner.id)).emit("comment:new", socketPayload);
  }
} catch (err) {
  console.error("Socket comment broadcast error:", err);
}
  res.json({ success: true, comment });
});

// Edit comment
app.patch("/api/buzz/posts/:postId/comments/:commentId", authMiddleware, async (req, res) => {
  await db.read();
  const { postId, commentId } = req.params;
  const { text } = req.body || {};
  const me = req.user.id;

  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: "post not found" });

  const post = owner.posts.find(p => p.id === postId);
  const comment = (post.comments || []).find(c => c.id === commentId);
  if (!comment) return res.status(404).json({ error: "comment not found" });
  if (comment.userId !== me) return res.status(403).json({ error: "not your comment" });

  comment.text = text.trim();
  await db.write();
  res.json({ success: true, comment });
});

// Delete comment (owner or commenter)
app.delete("/api/buzz/posts/:postId/comments/:commentId", authMiddleware, async (req, res) => {
  await db.read();
  const { postId, commentId } = req.params;
  const me = req.user.id;

  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: "post not found" });

  const post = owner.posts.find(p => p.id === postId);
  post.comments = (post.comments || []).filter(
    c => !(c.id === commentId && (c.userId === me || owner.id === me))
  );

  await db.write();
  res.json({ success: true });
});
*/ 

/* ======================
   POST REACTIONS & COMMENTS
====================== */

// Like/unlike a post  ✅ UPDATED WITH NOTIFICATION
app.post('/api/posts/:postId/react', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;
  const { action } = req.body || {}; // 'like' or 'unlike'

  const user = db.data.users.find(u =>
    (u.posts || []).some(p => p.id === postId)
  );
  if (!user) return res.status(404).json({ error: 'post not found' });

  const post = user.posts.find(p => p.id === postId);
  if (!post.reactions) post.reactions = {};

  const wasLiked = !!post.reactions[me];

  if (action === 'like') {
    post.reactions[me] = true;
  } else if (action === 'unlike') {
    delete post.reactions[me];
  }

  await db.write();

  // ✅ Send notification only when it's a *new* like (not unlike)
  if (action === 'like' && user.id !== me && !wasLiked) {
    try {
      await sendNotification(user.id, {
        fromId: me,
        type: "like",
        message: `liked your post ❤️`,
        href: `/viewProfile/${user.id}?post=${postId}&highlight=true`,
        entity: "post",
        entityId: postId,
        postId,
        postOwnerId: user.id,
      });
    } catch (err) {
      console.error("Like notification failed:", err);
    }
  }

  res.json({ success: true, likes: Object.keys(post.reactions).length });
});


// Comment on a post
app.post('/api/posts/:postId/comment', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'text required' });

  const user = db.data.users.find(u =>
    (u.posts || []).some(p => p.id === postId)
  );
  if (!user) return res.status(404).json({ error: 'post not found' });

  const post = user.posts.find(p => p.id === postId);
  if (!post.comments) post.comments = [];

  const comment = {
    id: shortid.generate(),
    userId: me,
    text,
    createdAt: Date.now(),
  };
  post.comments.push(comment);
  await db.write();

  res.json({ success: true, comment });
});
// --- Reaction (multiple emoji support, fixed for nested user.posts) ---
app.post('/api/posts/:postId/react-emoji', authMiddleware, async (req, res) => {
  try {
    await db.read();
    const me = req.user.id;
    const { postId } = req.params;
    const { emoji } = req.body || {};
    if (!emoji) return res.status(400).json({ error: "emoji required" });

    const allUsers = db.data.users || [];
    let postOwner = null;
    let post = null;

    for (const u of allUsers) {
      if (Array.isArray(u.posts)) {
        const p = u.posts.find((x) => x.id === postId);
        if (p) {
          postOwner = u;
          post = p;
          break;
        }
      }
    }

    if (!post) return res.status(404).json({ error: "post not found" });

    if (!post.reactions) post.reactions = {};
    if (!post.reactions[me]) post.reactions[me] = emoji;
    else if (post.reactions[me] === emoji) delete post.reactions[me];
    else post.reactions[me] = emoji;

    // ✅ compute counts properly
    const counts = {};
    for (const e of Object.values(post.reactions)) {
      counts[e] = (counts[e] || 0) + 1;
    }

    await db.write();

    res.json({
      success: true,
      counts,
      reactions: post.reactions,
    });
  } catch (err) {
    console.error("⚠️ react-emoji failed:", err);
    res.status(500).json({ error: "Reaction failed" });
  }
});


// --- Like / Unlike post (for feed + reels) ---
app.post('/api/buzz/posts/:postId/like', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;

  // find which user owns this post
  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: "post not found" });

  const post = owner.posts.find(p => p.id === postId);
  post.likes ||= [];

  const existing = post.likes.find(l => l.userId === me);
  if (existing) {
    // unlike
    post.likes = post.likes.filter(l => l.userId !== me);
  } else {
    const meUser = db.data.users.find(u => u.id === me) || {};
    post.likes.push({
      userId: me,
      name: `${meUser.firstName || ''} ${meUser.lastName || ''}`.trim(),
      avatar: meUser.avatar || '',
      createdAt: Date.now(),
    });

    // send notification to post owner (if not liking own post)
    if (owner.id !== me) {
      await sendNotification(owner.id, {
        fromId: me,
        type: "like",
        message: `${meUser.firstName || 'Someone'} liked your post ❤️`,
        entity: "post",
        entityId: postId,
        postId,
        postOwnerId: owner.id,
      });
    }
  }

  await db.write();
  res.json({ success: true, likes: post.likes });
});

// =======================================================
// ===  LetsBuzz feed (matched users only, not self)   ===
// =======================================================
app.get('/api/buzz/feed', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const qType = String(req.query.type || 'all').toLowerCase();

  // 1️⃣ Find matched user IDs (where both sides liked each other)
  const matchedIds = (db.data.matches || [])
    .filter(m => Array.isArray(m.users) && m.users.includes(me))
    .map(m => m.users.find(u => u !== me))
    .filter(Boolean);

  // 2️⃣ Gather posts from those matched users only
  const allUsers = db.data.users || [];
  const postsFromMatches = [];
  for (const u of allUsers) {
    if (!matchedIds.includes(u.id)) continue;
    for (const p of (u.posts || [])) {
      postsFromMatches.push({
        ...p,
        userId: u.id,
        _user: u, // temporary link to include user info
      });
    }
  }

  // 3️⃣ Filter by type (feed/reel/photo)
  let posts = postsFromMatches;
  if (qType !== 'all') {
    if (qType === 'reel' || qType === 'video') {
      posts = posts.filter(p =>
        p.type === 'reel' ||
        p.type === 'video' ||
        /\.(mp4|mov|webm|ogg)$/i.test(p.mediaUrl || '') ||
        /\/video\/upload\//i.test(p.mediaUrl || '')
      );
    } else {
      posts = posts.filter(p => (p.type || '').toLowerCase() === qType);
    }
  }

  // 4️⃣ Sort newest first
  posts.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  // 5️⃣ Serialize for frontend
  const serialized = posts.map(p => {
    const isOwner = p.userId === me;
    const likes = Array.isArray(p.likes) ? p.likes : [];
    return {
      id: p.id,
      text: p.text || '',
      mediaUrl: p.mediaUrl || '',
      type: p.type || 'photo',
      createdAt: p.createdAt || 0,
      userId: p.userId,
      user: {
        id: p._user.id,
        firstName: p._user.firstName || '',
        lastName: p._user.lastName || '',
        avatar: p._user.avatar || '',
      },
      isOwner,
      likesCount: likes.length,
      likes: isOwner ? likes : [], // only owner sees who liked
      comments: Array.isArray(p.comments) ? p.comments : [],
    };
  });

  res.json({ posts: serialized, hasMore: false });
});

// --- Like / Unlike a post (supports double-tap on frontend) ---
app.post('/api/posts/:postId/like', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;

  // locate post owner & post (your data model stores posts inside users)
  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: 'post not found' });

  const post = owner.posts.find(p => p.id === postId);
  post.likes ||= [];

  // toggle like
  const already = post.likes.find(l => l.userId === me);
  if (already) {
    post.likes = post.likes.filter(l => l.userId !== me);
  } else {
    const meUser = db.data.users.find(u => u.id === me) || {};
    post.likes.push({
      userId: me,
      name: `${meUser.firstName || ''} ${meUser.lastName || ''}`.trim(),
      avatar: meUser.avatar || '',
      createdAt: Date.now(),
    });
  }

  await db.write();
  res.json({ success: true, likesCount: post.likes.length });
});

// --- Get likes list: owner sees full list; others get count only ---
app.get('/api/posts/:postId/likes', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { postId } = req.params;

  const owner = db.data.users.find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: 'post not found' });

  const post = owner.posts.find(p => p.id === postId);
  const likes = post.likes || [];
  const isOwner = owner.id === me;

  if (isOwner) {
    // return full list (name + avatar) to owner only
    return res.json({ likes, likesCount: likes.length, isOwner: true });
  }
  // non-owners only get count
  return res.json({ likes: [], likesCount: likes.length, isOwner: false });
});

/* ======================
   EXTENDED POSTS & MEDIA (UPGRADE)
====================== */

// --- Edit Post (text or privacy) ---
app.patch('/api/posts/:postId', authMiddleware, async (req, res) => {
  const { postId } = req.params;
  const { text, privacy } = req.body || {};
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u => u.id === me);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const post = (user.posts || []).find(p => p.id === postId);
  if (!post) return res.status(404).json({ error: 'Post not found' });

  if (typeof text === 'string') post.text = text;
  if (privacy) post.privacy = privacy;

  await db.write();
  res.json({ success: true, post });
});

// --- Delete Post ---
app.delete('/api/posts/:postId', authMiddleware, async (req, res) => {
  const { postId } = req.params;
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u => u.id === me);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const before = user.posts.length;
  user.posts = user.posts.filter(p => p.id !== postId);
  const changed = before !== user.posts.length;
  if (changed) await db.write();

  res.json({ success: changed });
});

// --- Reactions (BuzzPost expects these endpoints/shape) ---
// Map: post.reactions = { [userId]: '❤️' }
app.post('/api/buzz/posts/:postId/react', authMiddleware, async (req, res) => {
  const { postId } = req.params;
  const { emoji } = req.body || {};
  if (!emoji) return res.status(400).json({ error: 'emoji required' });

  await db.read();
  const me = req.user.id;

  const owner = (db.data.users || []).find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: 'Post not found' });

  const post = owner.posts.find(p => p.id === postId);
  if (!post.reactions) post.reactions = {};

  const prev = post.reactions[me] || null;
  if (prev === emoji) {
    delete post.reactions[me];
  } else {
    post.reactions[me] = emoji;
  }

  await db.write();

  const reactionCounts = {};
  Object.values(post.reactions).forEach(e => {
    reactionCounts[e] = (reactionCounts[e] || 0) + 1;
  });
  const totalReactions = Object.keys(post.reactions).length;
  const myReaction = post.reactions[me] || null;

  try {
    if (io && post.userId && String(post.userId) !== String(me) && myReaction) {
      io.to(post.userId).emit('notification', {
        type: 'reaction',
        from: me,
        postId: post.id,
        emoji: myReaction,
        message: `${req.user.firstName || 'Someone'} reacted ${myReaction} to your post.`,
        timestamp: Date.now(),
      });
    }
  } catch {}

  return res.json({ success: true, myReaction, reactionCounts, totalReactions });
});

app.delete('/api/buzz/posts/:postId/react', authMiddleware, async (req, res) => {
  const { postId } = req.params;
  await db.read();
  const me = req.user.id;

  const owner = (db.data.users || []).find(u => (u.posts || []).some(p => p.id === postId));
  if (!owner) return res.status(404).json({ error: 'Post not found' });

  const post = owner.posts.find(p => p.id === postId);
  if (!post.reactions) post.reactions = {};
  const had = !!post.reactions[me];
  delete post.reactions[me];

  await db.write();

  const reactionCounts = {};
  Object.values(post.reactions).forEach(e => {
    reactionCounts[e] = (reactionCounts[e] || 0) + 1;
  });
  const totalReactions = Object.keys(post.reactions).length;

  return res.json({ success: had, myReaction: null, reactionCounts, totalReactions });
});

// --- Comment Edit ---
app.patch('/api/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  const { postId, commentId } = req.params;
  const { text } = req.body || {};
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u =>
    (u.posts || []).some(p => p.id === postId)
  );
  if (!user) return res.status(404).json({ error: 'Post not found' });

  const post = user.posts.find(p => p.id === postId);
  const comment = post.comments.find(c => c.id === commentId && c.userId === me);
  if (!comment) return res.status(404).json({ error: 'Comment not found or not yours' });

  comment.text = text;
  await db.write();
res.json({
  success: true,
  comment,
  comments: post.comments || [],
});
});

// --- Comment Delete ---
app.delete('/api/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  const { postId, commentId } = req.params;
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u =>
    (u.posts || []).some(p => p.id === postId)
  );
  if (!user) return res.status(404).json({ error: 'Post not found' });

  const post = user.posts.find(p => p.id === postId);
  const before = post.comments.length;
  post.comments = post.comments.filter(c => !(c.id === commentId && c.userId === me));
  const changed = before !== post.comments.length;
  if (changed) await db.write();

  res.json({ success: changed });
});
// --- React / unreact to a media item ---
app.post('/api/media/:ownerId/react', authMiddleware, async (req, res) => {
  await db.read();
  const me      = req.user.id;
  const ownerId = req.params.ownerId;
  const { mediaId, emoji = '❤️' } = req.body || {};
  if (!mediaId) return res.status(400).json({ error: 'mediaId required' });

  const owner = db.data.users.find(u => u.id === ownerId);
  if (!owner) return res.status(404).json({ error: 'owner not found' });

  const media = (owner.media || []).find(m => m.id === mediaId);
  if (!media) return res.status(404).json({ error: 'media not found' });

  if (!media.reactions) media.reactions = {}; // { userId: '❤️' }

  // toggle same emoji
  if (media.reactions[me] === emoji) {
    delete media.reactions[me];
  } else {
    media.reactions[me] = emoji;
  }

  await db.write();

  // counts by emoji
  const counts = {};
  Object.values(media.reactions).forEach(e => counts[e] = (counts[e] || 0) + 1);
  res.json({ ok: true, counts, mine: media.reactions[me] || null });
});

// --- Comment on a media item ---
app.post('/api/media/:ownerId/comment', authMiddleware, async (req, res) => {
  await db.read();
  const me      = req.user.id;
  const ownerId = req.params.ownerId;
  const { mediaId, text } = req.body || {};
  if (!mediaId || !text) return res.status(400).json({ error: 'mediaId & text required' });

  const owner = db.data.users.find(u => u.id === ownerId);
  if (!owner) return res.status(404).json({ error: 'owner not found' });

  const media = (owner.media || []).find(m => m.id === mediaId);
  if (!media) return res.status(404).json({ error: 'media not found' });

  if (!media.comments) media.comments = [];
  const comment = { id: shortid.generate(), userId: me, text, createdAt: Date.now() };
  media.comments.push(comment);
  await db.write();

  res.json({ ok: true, comment });
});

// --- Media Privacy Toggle ---
app.patch('/api/media/:id/privacy', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { privacy } = req.body || {}; // 'public' | 'private'
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u => u.id === me);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const media = user.media.find(m => m.id === id);
  if (!media) return res.status(404).json({ error: 'Media not found' });

  media.privacy = privacy || (media.privacy === 'private' ? 'public' : 'private');
  await db.write();

  res.json({ success: true, media });
});

// --- Delete Media ---
app.delete('/api/media/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  await db.read();

  const me = req.user.id;
  const user = db.data.users.find(u => u.id === me);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const before = user.media.length;
  user.media = user.media.filter(m => m.id !== id);
  const changed = before !== user.media.length;
  if (changed) await db.write();

  res.json({ success: changed });
});
// --- Buzz Feed: only matched users' posts, excluding my own ---
app.get('/api/buzz/feed', authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;

  // find all matches containing me
  const matchedIds = (db.data.matches || [])
    .filter(m => m.users && m.users.includes(me))
    .map(m => m.users.find(u => u !== me));

  const posts = [];
  for (const u of db.data.users) {
    if (!matchedIds.includes(u.id)) continue;
    for (const p of (u.posts || [])) {
      posts.push({
        ...p,
        user: {
          id: u.id,
          firstName: u.firstName,
          lastName: u.lastName,
          avatar: u.avatar,
        },
      });
    }
  }

  // exclude own posts just in case
  const filtered = posts.filter(p => p.user.id !== me);

  // optional type filter (reel/photo)
  const type = req.query.type;
  const final = type && type !== "all"
    ? filtered.filter(p => p.type === type)
    : filtered;

  // newest first
  final.sort((a, b) => b.createdAt - a.createdAt);

  res.json({ posts: final });
});


// =======================
// 🤖 SMART WINGMAN TIPS
// =======================
setInterval(async () => {
  await db.read();
  const users = db.data.users || [];
  if (users.length < 2) return;

  // Pick one random user to notify
  const target = users[Math.floor(Math.random() * users.length)];
  const nearby = users.filter(
    u =>
      u.id !== target.id &&
      u.location &&
      target.location &&
      distanceKm(u.location, target.location) < 10 // within 10 km
  );

  // Find shared interests or hobbies
  let match = null;
  for (const u of nearby) {
    const sharedInterests = (target.interests || []).filter(i =>
      (u.interests || []).includes(i)
    );
    const sharedHobbies = (target.hobbies || []).filter(h =>
      (u.hobbies || []).includes(h)
    );
    if (sharedInterests.length || sharedHobbies.length) {
      match = { user: u, sharedInterests, sharedHobbies };
      break;
    }
  }

  let message;
  if (match) {
    const name = match.user.firstName || "someone nearby";
    const common =
      match.sharedInterests[0] ||
      match.sharedHobbies[0] ||
      "similar vibes";
    message = `Wingman spotted ${name} nearby, you both love ${common}! 💞`;
  } else {
    const ideas = [
      "Wingman thinks your profile could use a fresh selfie 📸",
      "New people are buzzing in your area — go explore MicroBuzz 👀",
      "Add a voice intro to stand out 🎤",
      "Update your interests for better matches 💡",
    ];
    message = ideas[Math.floor(Math.random() * ideas.length)];
  }

 await sendNotification(target.id, {
  fromId: "system",
  type: "wingman",
  message,
  href: `/letsbuzz`,
});


  console.log("🤖 Wingman tip →", target.firstName || target.email, message);
}, 1000 * 60 * 30); // every 30 minutes

// -------------------- 🔥 BuzzStreak (Daily Check-in) --------------------

function todayKey() {
  return new Date().toISOString().split("T")[0];
}

// get streak
app.get("/api/streak/get", authMiddleware, async (req, res) => {
  await db.read();
  if (!db.data) db.data = {};
  if (!db.data.streaks) db.data.streaks = {};

  const userId = req.user.id;
  const entry = db.data.streaks[userId] || { count: 0, lastCheckIn: null };
  const today = todayKey();

  const checkedToday = entry.lastCheckIn === today;
  res.json({ streak: entry, checkedToday });
});

// check-in
app.post("/api/streak/checkin", authMiddleware, async (req, res) => {
  await db.read();
  if (!db.data) db.data = {};
  if (!db.data.streaks) db.data.streaks = {};

  const userId = req.user.id;
  const today = todayKey();
  const yesterday = new Date(Date.now() - 86400000)
    .toISOString()
    .split("T")[0];

  let entry = db.data.streaks[userId] || { count: 0, lastCheckIn: null };

  if (entry.lastCheckIn === today) {
    console.log("⏩ Already checked in today:", userId);
    return res.json({ streak: entry, checkedToday: true });
  }

  if (entry.lastCheckIn === yesterday) entry.count += 1;
  else entry.count = 1;

  entry.lastCheckIn = today;
  db.data.streaks[userId] = entry;
  await db.write();

  console.log("🔥 BuzzStreak updated:", { userId, entry });
  res.json({ streak: entry, checkedToday: true });
});

// =====================================================
// 💞 Meet-in-Middle (RomBuzz Free Local Version)
// =====================================================

// Save user’s location (lat, lng)
app.post("/api/geo/save", authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { lat, lng } = req.body || {};
  if (!lat || !lng) return res.status(400).json({ error: "Invalid coords" });

  const user = db.data.users.find((u) => u.id === me);
  if (user) {
    user.location = { lat, lng, updatedAt: Date.now() };
    await db.write();
    return res.json({ success: true });
  }
  res.status(404).json({ error: "User not found" });
});

// Fetch other user's location
app.get("/api/geo/approx", authMiddleware, async (req, res) => {
  await db.read();
  const { userId } = req.query;
  const user = db.data.users.find((u) => u.id === userId);
  if (!user?.location)
    return res.status(404).json({ error: "No location available" });
  res.json(user.location);
});

// Suggest local midpoint venues (static dataset - free)
app.get("/api/meet-suggest", authMiddleware, async (req, res) => {
  await db.read();
  const me = req.user.id;
  const { otherId } = req.query;
  const meUser = db.data.users.find((u) => u.id === me);
  const otherUser = db.data.users.find((u) => u.id === otherId);

  if (!meUser?.location || !otherUser?.location) {
    return res.status(400).json({ error: "Missing user locations" });
  }

  // Compute midpoint
  const midLat = (meUser.location.lat + otherUser.location.lat) / 2;
  const midLng = (meUser.location.lng + otherUser.location.lng) / 2;

  // Return static sample venues near midpoint (no API cost)
  const demoPlaces = [
    {
      name: "Buzz Café",
      vicinity: "Central Plaza",
      rating: 4.6,
      google_url: `https://www.openstreetmap.org/#map=18/${midLat}/${midLng}`,
    },
    {
      name: "RomBuzz Park",
      vicinity: "Downtown",
      rating: 4.8,
      google_url: `https://www.openstreetmap.org/#map=18/${midLat}/${midLng}`,
    },
    {
      name: "Sunset Lounge",
      vicinity: "Riverside",
      rating: 4.3,
      google_url: `https://www.openstreetmap.org/#map=18/${midLat}/${midLng}`,
    },
    {
      name: "Starlight Cinema",
      vicinity: "City Center",
      rating: 4.7,
      google_url: `https://www.openstreetmap.org/#map=18/${midLat}/${midLng}`,
    },
  ];

  res.json({ places: demoPlaces });
});

// =====================================================
// 💬 Socket.IO Meet Events
// =====================================================
io.on("connection", (socket) => {
  console.log("⚡ meet-user connected:", socket.id);

  // ✅ Map of online users { userId: socket.id }
  global.onlineUsers = global.onlineUsers || {};

  // --- User Registration ---
 socket.on("user:register", (userId) => {
  if (!userId) return;

  // ✅ Save to online map
  onlineUsers[userId] = socket.id;
  socket.userId = String(userId);

  // ✅ Join personal room so `io.to(userId)` works
  socket.join(String(userId));

  console.log("✅ Registered user:", userId, "→ socket:", socket.id, "(joined room)");
});
// 🧩 Legacy fallback for older clients
socket.on("register", (userId) => {
  if (userId) {
    onlineUsers[userId] = socket.id;
    socket.userId = userId;
    socket.join(String(userId));
    console.log("✅ Legacy register captured:", userId);
  }
});

  // --- Handle disconnect ---
  socket.on("disconnect", () => {
    for (const [uid, sid] of Object.entries(onlineUsers)) {
      if (sid === socket.id) delete onlineUsers[uid];
    }
    console.log("❌ Disconnected:", socket.id);
  });

   // ✅ Register user with socket ID for meet-in-middle and chat features
  socket.on("register", (userId) => {
    if (!userId) return;
    onlineUsers[userId] = socket.id;
    socket.userId = userId;

    console.log("✅ User registered:", userId, "→ socket:", socket.id);

    // 🔥 Broadcast online presence to all connected clients
    io.emit("presence:online", { userId });
  });

  // 🧹 Clean up on disconnect and broadcast offline presence
  socket.on("disconnect", () => {
    const userId = socket.userId;
    if (!userId) return;

    if (onlineUsers[userId]) {
      delete onlineUsers[userId];
      console.log("❌ User disconnected:", userId);

      // 🔥 Broadcast offline presence to all connected clients
      io.emit("presence:offline", { userId });
    }
  });

    socket.on("buzz_match_open_profile", (data) => {
    const { otherUserId } = data || {};
    if (!otherUserId) return;
    const senderId = socket.userId;

    // send to both users
    [senderId, otherUserId].forEach((id) => {
      if (onlineUsers[id]) {
        io.to(String(id)).emit("buzz_match_open_profile", {
          otherUserId: id === senderId ? otherUserId : senderId,
        });
      }
    });
    console.log(`💫 Open profile triggered between ${senderId} ↔ ${otherUserId}`);
  });

  // =======================
// 💌 MicroBuzz direct buzz relay (A → B popup)
// =======================
socket.on("buzz_request", (data) => {
  const { toId, fromId, selfieUrl, name, message } = data || {};
  if (!toId || !fromId) return;

  // Make sure both users exist in the map
  if (onlineUsers[toId]) {
    io.to(String(toId)).emit("buzz_request", {
      fromId,
      selfieUrl,
      name,
      message: message || "Someone nearby buzzed you!",
      type: "microbuzz",
    });
    console.log(`📡 Relayed buzz_request ${fromId} → ${toId}`);
  } else {
    console.log(`⚠️ Target ${toId} not online for buzz_request`);
  }
});


 // =====================================================
// 💞 Meet-in-the-Middle Events (final working version)
// =====================================================

// --- Meet Request (notify receiver for popup) ---
socket.on("meet:request", async ({ from, to }) => {
  try {
    if (!from || !to) return;
    await db.read();
    const sender = db.data.users.find(u => String(u.id) === String(from)) || { id: from };
    const sid = onlineUsers[to];
    if (sid) {
      io.to(sid).emit("meet:request", { from: sender });
      console.log(`📨 meet:request ${from} → ${to}`);
    }
  } catch (e) {
    console.error("meet:request error", e);
  }
});

// --- Meet Accept (store coords; compute midpoint when both shared) ---
socket.on("meet:accept", async ({ from, to, coords }) => {
  try {
    console.log("📍 meet:accept from", from, "→", to, coords);
    if (!from || !to) return;
    if (!coords || typeof coords.lat !== "number" || typeof coords.lng !== "number") return;

    await db.read();
    const me  = db.data.users.find(u => String(u.id) === String(from));
    const you = db.data.users.find(u => String(u.id) === String(to));
    if (!me || !you) return;

    // Save my latest coordinates
    me.location = { lat: Number(coords.lat), lng: Number(coords.lng) };
    await db.write();

    // If peer hasn't shared yet, send them mine and wait
    if (!you.location?.lat || !you.location?.lng) {
      const sid = onlineUsers[to];
      if (sid) io.to(sid).emit("meet:accept", { from, coords: me.location });
      return;
    }

    // Both shared → compute midpoint + fetch real places
    const res = await fetch("http://localhost:4000/api/meet/suggest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: me.location, b: you.location }),
    });
    const data = await res.json().catch(() => ({}));
    const places = Array.isArray(data.places) ? data.places : [];

    const payload = {
      from: { id: me.id, firstName: me.firstName, lastName: me.lastName },
      midpoint: data.midpoint || {
        lat: (me.location.lat + you.location.lat) / 2,
        lng: (me.location.lng + you.location.lng) / 2,
      },
      places,
    };

    const sidMe  = onlineUsers[me.id];
    const sidYou = onlineUsers[you.id];
    if (sidMe)  io.to(sidMe).emit("meet:suggest", payload);
    if (sidYou) io.to(sidYou).emit("meet:suggest", payload);
    console.log(`📍 meet:suggest → ${me.id}, ${you.id} (${places.length} places)`);
  } catch (e) {
    console.error("meet:accept error", e);
  }
});

// --- Meet Decline ---
socket.on("meet:decline", ({ from, to }) => {
  const sid = onlineUsers[to];
  if (sid) io.to(sid).emit("meet:decline", { from: { id: from } });
  console.log(`❌ meet:decline ${from} → ${to}`);
});

// --- Meet Place Chosen ---
socket.on("meet:chosen", ({ from, to, place }) => {
  const sid = onlineUsers[to];
  if (sid) io.to(sid).emit("meet:place:selected", { from: { id: from }, place });
  console.log(`🏠 meet:chosen ${from} → ${to} (${place?.name || "?"})`);
});
});
});


// =============== PRESENCE SNAPSHOT ===============
// Returns { online: true/false } for any user ID
app.get("/api/presence/:id", async (req, res) => {
  try {
    const id = req.params.id;
    // use your existing onlineUsers map from socket logic
    const isOnline = !!onlineUsers[id];
    res.json({ online: isOnline });
  } catch (e) {
    console.error("Presence check failed:", e);
    res.status(500).json({ error: "presence lookup failed" });
  }
});


/* ======================
   START SERVER
====================== */
server.listen(PORT, () => {
  console.log('✅ Rombuzz API running on', PORT);
});
