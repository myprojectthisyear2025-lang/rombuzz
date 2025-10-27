// routes/microbuzzRoutes.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const jwt = require("jsonwebtoken");

// === JWT setup (same secret as index.js) ===
const JWT_SECRET = process.env.JWT_SECRET || "rom_seed_dev_change_me";

// === Auth middleware ===
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }
  try {
    const token = h.split(" ")[1];
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// === File upload temp ===
const upload = multer({ dest: "uploads/" });

// === In-memory maps ===
let microbuzzSelfies = {};
let activeMicroBuzzUsers = {}; // { userId: { name, selfieUrl, lat, lng, lastActive } }

// === Distance helpers ===
function deg2rad(deg) {
  return deg * (Math.PI / 180);
}
function distanceMeters(lat1, lon1, lat2, lon2) {
  if (lat1 == null || lon1 == null || lat2 == null || lon2 == null) return Infinity;
  const R = 6371000;
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(deg2rad(lat1)) *
      Math.cos(deg2rad(lat2)) *
      Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// === Cleanup inactive users every 2 min ===
setInterval(() => {
  const now = Date.now();
  for (const id in activeMicroBuzzUsers) {
    if (now - activeMicroBuzzUsers[id].lastActive > 120000) {
      delete activeMicroBuzzUsers[id];
    }
  }
}, 60000);

// === LowDB setup ===
const dbFile = path.join(__dirname, "../db.json");
const adapter = new JSONFile(dbFile);
const db = new Low(adapter, { users: [], messages: [], likes: [], matches: [], blocks: [], reports: [] });

(async () => {
  await db.read();
  db.data ||= { users: [], messages: [], likes: [], matches: [], blocks: [], reports: [] };
})();

// ============================================
//   ROUTE FACTORY FUNCTION (with io support)
// ============================================
function initMicroBuzzRoutes(io, onlineUsers) {
  const router = express.Router();

  // 📸 Upload selfie (authenticated)
  router.post("/selfie", authMiddleware, upload.single("selfie"), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: "No selfie uploaded" });

      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "microbuzz_selfies",
        resource_type: "image",
        transformation: [{ width: 320, height: 320, crop: "fill", gravity: "face" }],
      });

      fs.unlink(req.file.path, () => {});
      const userId = req.user.id;
      microbuzzSelfies[userId] = result.secure_url;

      return res.json({ url: result.secure_url });
    } catch (err) {
      console.error("❌ MicroBuzz selfie upload failed:", err);
      res.status(500).json({ error: "Upload failed" });
    }
  });

  // ❌ Delete selfie (on deactivate)
  router.delete("/selfie", authMiddleware, async (req, res) => {
    try {
      const userId = req.user.id;
      delete microbuzzSelfies[userId];
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: "Delete failed" });
    }
  });

  // 🧭 Activate (share live presence)
  router.post("/activate", authMiddleware, express.json(), async (req, res) => {
    try {
      const { lat, lng, selfieUrl } = req.body;
      if (!lat || !lng || !selfieUrl)
        return res.status(400).json({ error: "Missing location or selfie" });

      const userId = req.user.id;
      const name = req.user.firstName || "Anonymous";

      activeMicroBuzzUsers[userId] = {
        name,
        selfieUrl,
        lat,
        lng,
        lastActive: Date.now(),
      };

      console.log(`📡 ${userId} activated MicroBuzz at (${lat}, ${lng})`);

      // Optionally emit presence update
      for (const [otherId, socketId] of Object.entries(onlineUsers)) {
        if (otherId !== userId) {
          io.to(socketId).emit("microbuzz_update", {
            userId,
            name,
            selfieUrl,
            lat,
            lng,
          });
        }
      }

      res.json({ ok: true });
    } catch (err) {
      console.error("❌ MicroBuzz activate error:", err);
      res.status(500).json({ error: "Internal error" });
    }
  });

  // 📴 Deactivate
  router.post("/deactivate", authMiddleware, (req, res) => {
    try {
      delete activeMicroBuzzUsers[req.user.id];
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: "Failed to deactivate" });
    }
  });

  // 📍 Get nearby users
  router.get("/nearby", authMiddleware, (req, res) => {
    try {
      const { lat, lng, radius = 0.2 } = req.query;
      const selfId = req.user.id;
      const now = Date.now();

      const list = Object.entries(activeMicroBuzzUsers)
        .filter(([id, info]) => id !== selfId && now - info.lastActive < 120000)
        .map(([id, info]) => ({
          id,
          name: info.name,
          selfieUrl: info.selfieUrl,
          distanceMeters: distanceMeters(lat, lng, info.lat, info.lng),
        }))
        .filter((u) => u.distanceMeters <= radius * 1000)
        .sort((a, b) => a.distanceMeters - b.distanceMeters);

      res.json({ users: list });
    } catch (err) {
      console.error("❌ MicroBuzz nearby error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // 🧪 Debug only (list all selfies)
  router.get("/selfies", authMiddleware, (req, res) => {
    res.json(microbuzzSelfies);
  });

  return router;
}

module.exports = initMicroBuzzRoutes;
