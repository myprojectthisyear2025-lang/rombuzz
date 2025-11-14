/**
 * ============================================================
 * 📁 File: routes/likesMatches.js
 * 🧩 Purpose: Handle Likes, Matches, Buzz, MatchStreak, and Social Stats.
 *
 * Endpoints:
 *   POST /api/likes                     → Like / Buzz request
 *   POST /api/buzz                      → Buzz between matched users
 *   GET  /api/likes/status/:id          → Get like/match status with user
 *   GET  /api/matches                   → Get all matches
 *   GET  /api/matchstreak/:id           → Get directed MatchStreak info
 *   POST /api/unmatch/:id               → Unmatch user
 *   GET  /api/social-stats              → Social counts (likes, matches)
 *   GET  /api/social/:type              → Lists (liked / likedYou / matches)
 *
 * Dependencies:
 *   - models/User.js        → Mongoose schema for users
 *   - models/Like.js        → Mongoose schema for likes
 *   - models/Match.js       → Mongoose schema for matches
 *   - models/MatchStreak.js → Optional streak tracking
 *   - authMiddleware.js     → JWT validation
 *   - utils/helpers.js      → isBlocked, baseSanitizeUser, incMatchStreakOut
 *   - io, onlineUsers       → from socket.js
 *   - sendNotification()    → notify matched or buzzed users
 *
 * Notes:
 *   - Core of matchmaking logic (Buzz + Match + Streaks)
 *   - Used by Discover, ViewProfile, Chat, and Notifications modules
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("../routes/auth-middleware");
const shortid = require("shortid");

const User = require("../models/User");
const Relationship = require("../models/Relationship"); // ✅ unified model for likes, blocks, follows
const Match = require("../models/Match");
const MatchStreak = require("../models/MatchStreak"); // optional schema
const {
  baseSanitizeUser,
  sendNotification,
  isBlocked,
  incMatchStreakOut,
} = require("../utils/helpers");

const { io, onlineUsers } = global;
const ENABLE_LIKES_MATCHES = true;
const buzzLocks = new Set();

/* ======================
   ❤️ LIKE / MATCH
====================== */
router.post("/likes", authMiddleware, async (req, res) => {
  if (!ENABLE_LIKES_MATCHES)
    return res.status(403).json({ error: "likes disabled" });

  try {
    const { to } = req.body;
    if (!to) return res.status(400).json({ error: "to required" });
    const from = req.user.id;

    if (isBlocked(from, to))
      return res.status(403).json({ error: "blocked" });

  // 💞 Already liked?
const existing = await Relationship.findOne({ from, to, type: "like" });
if (existing)
  return res.status(400).json({ error: "already liked" });

// 💞 Create like
await Relationship.create({ from, to, type: "like", createdAt: new Date() });

// 💞 Check mutual like → MATCH
const mutual = await Relationship.findOne({ from: to, to: from, type: "like" });
 const self = await User.findOne({ id: from }).lean();
    const other = await User.findOne({ id: to }).lean();

    if (mutual) {
      const existsMatch = await Match.findOne({ users: { $all: [from, to] } });
      if (!existsMatch) {
        await Match.create({
          id: shortid.generate(),
          users: [from, to],
          createdAt: new Date(),
        });
      }

     // 🧹 Cleanup both likes
await Relationship.deleteMany({
  $or: [
    { from, to, type: "like" },
    { from: to, to: from, type: "like" },
  ],
});


      // 🔔 Socket events
      const selfSocket = onlineUsers[from];
      const targetSocket = onlineUsers[to];
      if (selfSocket) io.to(selfSocket).emit("match", { otherUserId: to });
      if (targetSocket) io.to(targetSocket).emit("match", { otherUserId: from });

      // 📨 Notifications
      const fromName = self?.firstName || "Someone";
      const otherName = other?.firstName || "Someone";
      await sendNotification(to, {
        fromId: from,
        type: "buzz",
        message: `${fromName} wants to match with you! 💖`,
        href: `/viewProfile/${from}`,
      });
      await sendNotification(from, {
        fromId: to,
        type: "match",
        message: `💞 It's a match with ${otherName}!`,
        href: `/viewProfile/${to}`,
      });
    } else {
      // 💌 Buzz request (first like)
      const targetSocket = onlineUsers[to];
      if (targetSocket) {
        const fromUser = baseSanitizeUser(self);
        io.to(targetSocket).emit("buzz_request", {
          fromId: from,
          name: fromUser.firstName || "Someone nearby",
          selfieUrl: fromUser.avatar || "",
        });
      }
      const fromName = self?.firstName || "Someone nearby";
      await sendNotification(to, {
        fromId: from,
        type: "buzz",
        message: `${fromName} wants to match with you! 💖`,
      });
    }

    res.json({ success: true, matched: !!mutual });
  } catch (err) {
    console.error("❌ LIKE error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

/* ======================
   💖 BUZZ BETWEEN MATCHED USERS
====================== */
router.post("/buzz", authMiddleware, async (req, res) => {
  const fromId = req.user.id;
  const { to } = req.body || {};
  if (!to) return res.status(400).json({ error: "to required" });

  const pairKey = [String(fromId), String(to)].sort().join("_");
  if (buzzLocks.has(pairKey))
    return res.status(429).json({ error: "busy" });
  buzzLocks.add(pairKey);

  try {
    // ✅ Ensure both are matched
    const matched = await Match.findOne({ users: { $all: [fromId, to] } });
    if (!matched) return res.status(409).json({ error: "not_matched" });

    if (isBlocked(fromId, to))
      return res.status(403).json({ error: "blocked" });

    // 🔥 Buzz cooldown (memory-based)
    const now = Date.now();
    const COOLDOWN_MS = 10 * 1000;
    global._buzzCooldown ||= {};
    const last = global._buzzCooldown[pairKey] || 0;
    if (now - last < COOLDOWN_MS) {
      return res.status(429).json({
        error: "cooldown",
        retryInMs: COOLDOWN_MS - (now - last),
      });
    }
    global._buzzCooldown[pairKey] = now;

    // 🔥 Update streak
    const streakObj = await incMatchStreakOut(fromId, to);
    const currentStreak = Number(streakObj?.count || 0);

    const sender = await User.findOne({ id: fromId }).lean();
    const fromName = sender?.firstName || "Someone";
    let message = `${fromName} buzzed you! Buzz them back! 💖`;
    if (currentStreak > 1)
      message += `\n🔥 MatchStreak: ${currentStreak}`;
    else if (currentStreak === 1)
      message += `\n🎉 Start a MatchStreak!`;

    await sendNotification(to, {
      fromId,
      type: "buzz",
      message,
      href: `/viewProfile/${fromId}`,
      streak: currentStreak,
    });

    console.log(`✅ Buzz OK. Streak now ${currentStreak}`);
    return res.json({ success: true, streak: currentStreak });
  } catch (e) {
    console.error("❌ Buzz endpoint error:", e);
    return res.status(500).json({ error: "internal_error" });
  } finally {
    buzzLocks.delete(pairKey);
  }
});

/* ======================
   ❤️ STATUS & MATCH LISTS
====================== */
router.get("/likes/status/:targetUserId", authMiddleware, async (req, res) => {
  try {
    const targetId = req.params.targetUserId;
    const selfId = req.user.id;

   const likedByMe = await Relationship.exists({ from: selfId, to: targetId, type: "like" });
const likedMe = await Relationship.exists({ from: targetId, to: selfId, type: "like" });
 const matched = await Match.exists({ users: { $all: [selfId, targetId] } });

    res.json({ likedByMe: !!likedByMe, likedMe: !!likedMe, matched: !!matched });
  } catch (e) {
    console.error("Status error:", e);
    res.status(500).json({ error: "internal_error" });
  }
});

router.get("/matches", authMiddleware, async (req, res) => {
  try {
    const selfId = req.user.id;
    const matchDocs = await Match.find({ users: selfId }).lean();
    const ids = matchDocs
      .map((m) => m.users.find((id) => id !== selfId))
      .filter(Boolean);

    const users = await User.find({ id: { $in: ids } }).lean();
    const result = users.map((u) => ({
      id: u.id,
      firstName: u.firstName,
      lastName: u.lastName,
      avatar: u.avatar || "https://via.placeholder.com/150x150?text=No+Photo",
      bio: u.bio || "",
      gender: u.gender || "",
      verified: !!u.verified,
    }));

    res.json(result);
  } catch (e) {
    console.error("Matches fetch error:", e);
    res.status(500).json({ error: "internal_error" });
  }
});

/* ======================
   🔥 MATCHSTREAK
====================== */
router.get("/matchstreak/:otherUserId", authMiddleware, async (req, res) => {
  try {
    const myId = String(req.user.id);
    const otherId = String(req.params.otherUserId);

    const streak = await MatchStreak.findOne({ from: myId, to: otherId }).lean();
    const payload = streak
      ? {
          from: streak.from,
          to: streak.to,
          count: Number(streak.count || 0),
          lastBuzz: streak.lastBuzz || null,
          createdAt: streak.createdAt || null,
        }
      : { from: myId, to: otherId, count: 0, lastBuzz: null, createdAt: null };

    res.json({ streak: payload });
  } catch (e) {
    console.error("MatchStreak error:", e);
    res.status(500).json({ error: "internal_error" });
  }
});

/* ======================
   💔 UNMATCH
====================== */
router.post("/unmatch/:id", authMiddleware, async (req, res) => {
  try {
    const me = req.user.id;
    const them = req.params.id;

    const before = await Match.countDocuments({});
    await Match.deleteMany({ users: { $all: [me, them] } });
    await Relationship.deleteMany({
  $or: [
    { from: me, to: them, type: "like" },
    { from: them, to: me, type: "like" },
  ],
});


    const after = await Match.countDocuments({});
    const removed = before !== after;
    res.json({ ok: true, unmatched: removed });
  } catch (e) {
    console.error("Unmatch error:", e);
    res.status(500).json({ error: "Could not unmatch" });
  }
});

/* ======================
   📊 SOCIAL STATS & LISTS
====================== */
router.get("/social-stats", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
const likes = await Relationship.find({ type: "like" }).lean();
    const matches = await Match.find({}).lean();

    const liked = likes.filter((l) => l.from === userId).map((l) => l.to);
    const likedYou = likes.filter((l) => l.to === userId).map((l) => l.from);
    const matched = matches.filter((m) => m.users.includes(userId));

    res.json({
      likedCount: liked.length,
      likedYouCount: likedYou.length,
      matchCount: matched.length,
    });
  } catch (e) {
    console.error("Social stats error:", e);
    res.status(500).json({ error: "internal_error" });
  }
});

router.get("/social/:type", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const type = req.params.type;

const likes = await Relationship.find({ type: "like" }).lean();
    const matches = await Match.find({}).lean();
    const users = await User.find({}).lean();

    let targetIds = [];
    if (type === "liked") {
      targetIds = likes.filter((l) => l.from === userId).map((l) => l.to);
    } else if (type === "likedYou") {
      targetIds = likes.filter((l) => l.to === userId).map((l) => l.from);
    } else if (type === "matches") {
      targetIds = matches
        .filter((m) => m.users.includes(userId))
        .map((m) => m.users.find((id) => id !== userId));
    } else return res.status(400).json({ error: "Invalid type" });

    const idSet = new Set(targetIds);
    const result = users
      .filter((u) => idSet.has(u.id))
      .map((u) => ({
        id: u.id,
        firstName: u.firstName || "",
        lastName: u.lastName || "",
        avatar: u.avatar || "https://via.placeholder.com/150x150?text=No+Photo",
        bio: u.bio || "",
        gender: u.gender || "",
        verified: !!u.verified,
      }));

    res.json(result);
  } catch (e) {
    console.error("Social list error:", e);
    res.status(500).json({ error: "internal_error" });
  }
});

module.exports = router;
