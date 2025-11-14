/**
 * ============================================================
 * 📁 File: routes/likeRoutes.js
 * 💖 Purpose: Handles "Buzz" (like) interactions and mutual matches.
 *
 * Endpoints:
 *   POST /api/likes                  → Buzz someone (create like or match)
 *
 * Features:
 *   - Creates one-way "like" when a user buzzes another
 *   - Detects mutual likes and upgrades them to a match
 *   - Removes redundant like entries upon match creation
 *   - Emits real-time Socket.IO events:
 *       • "buzz_request" → When someone likes you
 *       • "match"        → When mutual like forms a match
 *
 * Dependencies:
 *   - models/Like.js        → MongoDB schema for likes
 *   - models/Match.js       → MongoDB schema for matches
 *   - auth-middleware.js    → JWT validation for route protection
 *
 * Notes:
 *   - Replaces legacy LowDB version with MongoDB
 *   - Uses initLikeRoutes(io, onlineUsers) for socket binding
 * ============================================================
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const Like = require("../models/Like");
const Match = require("../models/Match");
const User = require("../models/User"); // optional, for existence check

module.exports = function initLikeRoutes(io, onlineUsers) {
  const router = express.Router();

  /* ============================================================
     🔐 AUTH MIDDLEWARE
  ============================================================ */
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

  /* ============================================================
     📡 POST /api/likes  → Buzz someone
     ------------------------------------------------------------
     - Creates a like document: { from, to }
     - If reverse like exists → creates a match
     - Emits:
         - "buzz_request" to target if one-way like
         - "match" to both users on mutual like
  ============================================================ */
  router.post("/", auth, async (req, res) => {
    try {
      const from = String(req.userId);
      const to = String(req.body.to);
      if (!to) return res.status(400).json({ error: "Missing target user ID" });

      // 🧠 1️⃣ Check if already matched
      const existingMatch = await Match.findOne({
        users: { $all: [from, to] },
      });
      if (existingMatch) {
        return res.json({ message: "Already matched", matched: true });
      }

      // 🧠 2️⃣ Check if target already liked me (reverse like)
      const reverseLike = await Like.findOne({ from: to, to: from });
      if (reverseLike) {
        // 🧩 Create match
        await Match.create({
          id: `${from}_${to}_${Date.now()}`,
          users: [from, to],
          createdAt: new Date(),
        });

        // 🧹 Clean up both likes
        await Like.deleteMany({
          $or: [
            { from, to },
            { from: to, to: from },
          ],
        });

        // 🔔 Notify both users (Socket.IO)
        const fromSocket = onlineUsers[from];
        const toSocket = onlineUsers[to];
        if (fromSocket) io.to(fromSocket).emit("match", { otherUserId: to });
        if (toSocket) io.to(toSocket).emit("match", { otherUserId: from });

        return res.json({ matched: true });
      }

      // 🧠 3️⃣ Check if I already liked them before
      const existingLike = await Like.findOne({ from, to });
      if (existingLike) {
        return res.json({ alreadyLiked: true });
      }

      // 💖 4️⃣ Otherwise, create a new like
      await Like.create({
        from,
        to,
        createdAt: new Date(),
      });

      // 🔔 Notify target (buzz_request)
      const targetSocket = onlineUsers[to];
      if (targetSocket) {
        io.to(targetSocket).emit("buzz_request", { fromId: from });
      }

      res.json({ message: "Buzz sent" });
    } catch (err) {
      console.error("❌ Buzz/Like error:", err);
      res.status(500).json({ error: "Failed to send buzz" });
    }
  });

  return router;
};
