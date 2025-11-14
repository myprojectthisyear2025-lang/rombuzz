/**
 * ============================================================
 * 📁 File: routes/stories.js
 * 🧩 Purpose: Manage 24-hour stories (upload, view, cleanup)
 *
 * Endpoints:
 *   POST   /api/stories                 → Upload a story (image/video via URL)
 *   POST   /api/stories/upload          → Upload a story via file (multipart)
 *   GET    /api/stories                 → Fetch all active stories
 *   DELETE /api/stories/cleanup         → Remove expired stories
 *
 * Features:
 *   - Fully migrated to MongoDB (StoryModel)
 *   - Supports both URL and file uploads
 *   - Auto-expires after 24 hours
 *   - Associates each story with its user
 *   - Returns media type (video/image)
 *   - Includes cleanup route for expired stories
 *
 * Dependencies:
 *   - models/StoryModel.js    → MongoDB schema for stories
 *   - models/User.js          → User reference
 *   - auth-middleware.js      → Validates user token
 *   - cloudinary.v2           → Media upload
 *   - multer + fs             → File handling
 *
 * Notes:
 *   - Used by StoriesBar.jsx and CreateStory.jsx
 *   - Automatically cleans up expired stories
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const fs = require("fs");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");

const upload = multer({ dest: "uploads/" });
const authMiddleware = require("../routes/auth-middleware");

const StoryModel = require("../models/StoryModel");
const User = require("../models/User");

/* ============================================================
   📸 POST /api/stories  → Upload via direct media URL
============================================================ */
router.post("/", authMiddleware, async (req, res) => {
  try {
    const { mediaUrl, text = "" } = req.body || {};
    if (!mediaUrl)
      return res.status(400).json({ error: "mediaUrl required" });

    const user = await User.findOne({ id: req.user.id }).lean();
    if (!user)
      return res.status(404).json({ error: "User not found" });

    const story = await StoryModel.create({
      id: shortid.generate(),
      userId: user.id,
      mediaUrl,
      text,
      type: /\.(mp4|mov|webm|ogg)$/i.test(mediaUrl) ? "video" : "image",
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      isActive: true,
      views: [],
    });

    res.json({ success: true, story });
  } catch (err) {
    console.error("❌ Story upload (URL) failed:", err);
    res.status(500).json({ error: "Failed to create story" });
  }
});

/* ============================================================
   📤 POST /api/stories/upload  → Upload via file (multipart)
============================================================ */
router.post("/upload", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    const file = req.file;
    if (!file)
      return res.status(400).json({ error: "No media uploaded" });

    const uploadRes = await cloudinary.uploader.upload(file.path, {
      folder: "rombuzz_stories",
      resource_type: "auto",
    });
    fs.unlinkSync(file.path);

    const story = await StoryModel.create({
      id: shortid.generate(),
      userId: req.user.id,
      mediaUrl: uploadRes.secure_url,
      type: uploadRes.resource_type === "video" ? "video" : "image",
      createdAt: Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      isActive: true,
      views: [],
    });

    res.json({ success: true, story });
  } catch (err) {
    console.error("❌ Story upload (file) failed:", err);
    res.status(500).json({ error: "Failed to upload story" });
  }
});

/* ============================================================
   📖 GET /api/stories  → Fetch all active stories
============================================================ */
router.get("/", authMiddleware, async (req, res) => {
  try {
    const now = Date.now();
    const stories = await StoryModel.find({
      isActive: true,
      expiresAt: { $gt: now },
    })
      .sort({ createdAt: -1 })
      .lean();

    res.json({ stories });
  } catch (err) {
    console.error("❌ GET /stories error:", err);
    res.status(500).json({ error: "Failed to load stories" });
  }
});

/* ============================================================
   🧹 DELETE /api/stories/cleanup  → Remove expired stories
============================================================ */
router.delete("/cleanup", async (req, res) => {
  try {
    const result = await StoryModel.deleteMany({
      expiresAt: { $lte: Date.now() },
    });

    console.log(`🧹 Cleaned up ${result.deletedCount} expired stories`);
    res.json({ cleaned: true, deleted: result.deletedCount });
  } catch (err) {
    console.error("❌ Story cleanup failed:", err);
    res.status(500).json({ error: "Cleanup failed" });
  }
});

module.exports = router;
