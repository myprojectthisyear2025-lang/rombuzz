/**
 * ============================================================
 * 📁 File: routes/upload.js
 * ☁️ Purpose: Handles authenticated Cloudinary uploads for avatars, posts, and stories.
 *
 * Endpoints:
 *   POST /api/upload-avatar-url      → Save existing Cloudinary avatar URL
 *   POST /api/upload-avatar          → Upload avatar (auto type)
 *   POST /api/upload-avatar-facecrop → Upload + face crop avatar (new merged)
 *   POST /api/upload-media-file      → Upload photo/video file to Cloudinary
 *   POST /api/upload-media           → Save frontend-uploaded media metadata
 *
 * Features:
 *   - Fully migrated to MongoDB (User model)
 *   - Supports both URL-based & multipart uploads
 *   - Optional face-crop for circular avatars
 *   - Authenticated via JWT
 *   - Cleans temp files & updates user.media array
 *
 * Dependencies:
 *   - cloudinary.v2 / multer / fs / shortid / mongoose User
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const fs = require("fs");
const shortid = require("shortid");
const { v2: cloudinary } = require("cloudinary");
const upload = require("../config/multer");
const authMiddleware = require("../routes/auth-middleware");
const User = require("../models/User");

/* ============================================================
   🧩 1️⃣ AVATAR UPLOAD (Frontend URL)
============================================================ */
router.post("/upload-avatar-url", authMiddleware, async (req, res) => {
  try {
    const { avatarUrl } = req.body || {};
    if (!avatarUrl)
      return res.status(400).json({ error: "avatarUrl required" });

    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    // ✅ Update avatar + media array
    user.avatar = avatarUrl;
    user.media ||= [];
    user.media.unshift({
      id: shortid.generate(),
      url: avatarUrl,
      type: "image",
      caption: "facebuzz",
      privacy: "public",
      createdAt: Date.now(),
    });
    await user.save();

    res.json({ url: avatarUrl, user });
  } catch (err) {
    console.error("❌ /upload-avatar-url error:", err);
    res.status(500).json({ error: "Failed to set avatar" });
  }
});

/* ============================================================
   🧩 2️⃣ AVATAR UPLOAD (default auto upload)
============================================================ */
router.post("/upload-avatar", authMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ error: "No file uploaded" });

    const uploaded = await cloudinary.uploader.upload(req.file.path, {
      folder: process.env.CLOUDINARY_AVATAR_FOLDER || "rombuzz_uploads/avatars",
      resource_type: "auto",
      overwrite: true,
    });
    try { fs.unlinkSync(req.file.path); } catch {}

    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    user.avatar = uploaded.secure_url;
    await user.save();

    res.json({ url: uploaded.secure_url, user });
  } catch (err) {
    console.error("❌ /upload-avatar error:", err);
    res.status(500).json({ error: "Avatar upload failed" });
  }
});

/* ============================================================
   🧩 3️⃣ AVATAR UPLOAD (face-cropped version — merged from index.js)
============================================================ */
router.post("/upload-avatar-facecrop", authMiddleware, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ error: "No file uploaded" });

    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "rombuzz/avatars",
      resource_type: "image",
      transformation: [
        { width: 400, height: 400, crop: "fill", gravity: "face", radius: "max" },
      ],
    });
    fs.unlink(req.file.path, () => {});

    const user = await User.findOneAndUpdate(
      { id: req.user.id },
      { $set: { avatar: result.secure_url } },
      { new: true }
    );

    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ url: result.secure_url, public_id: result.public_id });
  } catch (err) {
    console.error("❌ /upload-avatar-facecrop error:", err);
    res.status(500).json({ error: "Avatar upload failed" });
  }
});

/* ============================================================
   🧩 4️⃣ GENERIC MEDIA UPLOAD (multipart)
============================================================ */
router.post("/upload-media-file", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ error: "No file uploaded" });

    const uploaded = await cloudinary.uploader.upload(req.file.path, {
      folder: process.env.CLOUDINARY_MEDIA_FOLDER || "rombuzz_uploads/posts",
      resource_type: "auto",
      overwrite: true,
    });
    try { fs.unlinkSync(req.file.path); } catch {}

    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    const mediaItem = {
      id: shortid.generate(),
      url: uploaded.secure_url,
      type: uploaded.resource_type === "video" ? "video" : "image",
      caption: "",
      privacy: "public",
      createdAt: Date.now(),
    };

    user.media ||= [];
    user.media.unshift(mediaItem);
    await user.save();

    res.json({
      ok: true,
      url: uploaded.secure_url,
      type: mediaItem.type,
      media: mediaItem,
    });
  } catch (err) {
    console.error("❌ /upload-media-file error:", err);
    res.status(500).json({ error: "Media upload failed" });
  }
});

/* ============================================================
   🧩 5️⃣ FRONTEND MEDIA METADATA SAVE
============================================================ */
router.post("/upload-media", authMiddleware, async (req, res) => {
  try {
    const { fileUrl, type, caption } = req.body || {};
    if (!fileUrl)
      return res.status(400).json({ error: "fileUrl is required" });

    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    const mediaItem = {
      id: shortid.generate(),
      url: fileUrl,
      type: type === "video" ? "video" : "image",
      caption: caption || "",
      createdAt: Date.now(),
    };

    user.media ||= [];
    user.media.unshift(mediaItem);
    await user.save();

    res.json({ success: true, media: user.media });
  } catch (err) {
    console.error("❌ /upload-media error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

console.log("✅ Upload routes initialized (MongoDB)");
module.exports = router;
