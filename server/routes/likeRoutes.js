// routes/likeRoutes.js
const express = require("express");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

module.exports = function initLikeRoutes(io, onlineUsers) {
  const router = express.Router();

  // === Init DB ===
  const dbPath = path.join(__dirname, "..", "db.json");
  if (!fs.existsSync(dbPath))
    fs.writeFileSync(dbPath, JSON.stringify({ users: [], likes: [], matches: [] }, null, 2));

  const db = new Low(new JSONFile(dbPath), { users: [], likes: [], matches: [] });
  (async () => {
    await db.read();
    db.data ||= { users: [], likes: [], matches: [] };
    await db.write();
  })();

  // === Middleware ===
  function auth(req, res, next) {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ error: "Missing token" });
      const decoded = jwt.verify(token, process.env.JWT_SECRET || "rom_seed_dev_change_me");
      req.userId = decoded.id;
      next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  }

  // =============================
  // 📡 POST /api/likes  → Buzz someone
  // =============================
  router.post("/", auth, async (req, res) => {
    const from = String(req.userId);
    const to = String(req.body.to);
    if (!to) return res.status(400).json({ error: "Missing target user ID" });

    await db.read();
    db.data.likes ||= [];
    db.data.matches ||= [];

    // If both users already matched → short-circuit
    const alreadyMatched = db.data.matches.find(m =>
      m.users.includes(from) && m.users.includes(to)
    );
    if (alreadyMatched) {
      return res.json({ message: "Already matched", matched: true });
    }

    // Check if target already liked me → MATCH!
    const reverseLike = db.data.likes.find(l => l.from === to && l.to === from);
    if (reverseLike) {
      // Create a match
      db.data.matches.push({
        users: [from, to],
        createdAt: Date.now(),
      });

      // Remove both like entries
      db.data.likes = db.data.likes.filter(
        l => !( (l.from === from && l.to === to) || (l.from === to && l.to === from) )
      );

      await db.write();

      // Notify both users
      const fromSocket = onlineUsers[from];
      const toSocket = onlineUsers[to];
      if (fromSocket) io.to(fromSocket).emit("match", { otherUserId: to });
      if (toSocket) io.to(toSocket).emit("match", { otherUserId: from });

      return res.json({ matched: true });
    }

    // Otherwise: check if I already liked them before
    const existing = db.data.likes.find(l => l.from === from && l.to === to);
    if (existing) {
      return res.json({ alreadyLiked: true });
    }

    // Otherwise, save new like
    db.data.likes.push({ from, to, timestamp: Date.now() });
    await db.write();

    // Notify target (buzz_request)
    const targetSocket = onlineUsers[to];
    if (targetSocket) {
      io.to(targetSocket).emit("buzz_request", { fromId: from });
    }

    res.json({ message: "Buzz sent" });
  });

  return router;
};
