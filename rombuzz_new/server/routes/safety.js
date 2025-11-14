/**
 * ============================================================
 * 📁 File: routes/safety.js
 * 🛡️ Purpose: Handle user blocking, unblocking, reporting, and moderation.
 *
 * Endpoints:
 *   POST /api/block           → Block a user
 *   POST /api/unblock         → Unblock a user
 *   GET  /api/blocks          → List blocked users
 *   POST /api/report          → Report a user with reason
 *   GET  /api/reports         → View own (or all, if admin) reports
 *
 * Features:
 *   - Uses MongoDB collections instead of LowDB
 *   - Unified Relationship model for block/unblock
 *   - ReportModel for user reports with admin visibility
 *   - Sanitizes user data for safe frontend rendering
 *
 * Dependencies:
 *   - models/Relationship.js  → Stores block relations
 *   - models/ReportModel.js   → Stores user reports
 *   - models/User.js          → User data for decoration
 *   - authMiddleware.js       → JWT validation
 *   - utils/helpers.js        → baseSanitizeUser()
 *
 * Notes:
 *   - Used in Settings → Safety → Blocked Users & Report User
 *   - ADMIN_EMAIL environment variable grants moderation access
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const shortid = require("shortid");
const authMiddleware = require("../routes/auth-middleware");
const { baseSanitizeUser } = require("../utils/helpers");

const Relationship = require("../models/Relationship");
const ReportModel = require("../models/ReportModel");
const User = require("../models/User");

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";

/* ======================
   🚫 BLOCK / UNBLOCK
====================== */

// ✅ Block a user
router.post("/block", authMiddleware, async (req, res) => {
  try {
    const { targetId } = req.body || {};
    if (!targetId)
      return res.status(400).json({ error: "targetId required" });

    // Prevent duplicate block
    const exists = await Relationship.exists({
      from: req.user.id,
      to: targetId,
      type: "block",
    });

    if (!exists) {
      await Relationship.create({
        id: shortid.generate(),
        from: req.user.id,
        to: targetId,
        type: "block",
        createdAt: Date.now(),
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("❌ POST /block error:", err);
    res.status(500).json({ error: "Failed to block user" });
  }
});

// ✅ Unblock a user
router.post("/unblock", authMiddleware, async (req, res) => {
  try {
    const { targetId } = req.body || {};
    if (!targetId)
      return res.status(400).json({ error: "targetId required" });

    const result = await Relationship.deleteOne({
      from: req.user.id,
      to: targetId,
      type: "block",
    });

    res.json({ success: true, changed: result.deletedCount > 0 });
  } catch (err) {
    console.error("❌ POST /unblock error:", err);
    res.status(500).json({ error: "Failed to unblock user" });
  }
});

// ✅ List all blocked users
router.get("/blocks", authMiddleware, async (req, res) => {
  try {
    const blocks = await Relationship.find({
      from: req.user.id,
      type: "block",
    }).lean();

    if (!blocks.length) return res.json({ blocks: [] });

    const blockedIds = blocks.map((b) => b.to);
    const users = await User.find({ id: { $in: blockedIds } }).lean();
    const userMap = new Map(users.map((u) => [u.id, baseSanitizeUser(u)]));

    const list = blocks.map((b) => ({
      ...b,
      user: userMap.get(b.to) || null,
    }));

    res.json({ blocks: list });
  } catch (err) {
    console.error("❌ GET /blocks error:", err);
    res.status(500).json({ error: "Failed to fetch blocked users" });
  }
});

/* ======================
   🚨 REPORTS
====================== */

// ✅ Create a user report
router.post("/report", authMiddleware, async (req, res) => {
  try {
    const { targetId, reason } = req.body || {};
    if (!targetId || !reason)
      return res.status(400).json({ error: "targetId & reason required" });

    const report = await ReportModel.create({
      id: shortid.generate(),
      from: req.user.id,
      targetId,
      reason,
      status: "open",
      createdAt: Date.now(),
    });

    res.json({ success: true, report });
  } catch (err) {
    console.error("❌ POST /report error:", err);
    res.status(500).json({ error: "Failed to submit report" });
  }
});

// ✅ Get reports (own or all if admin)
router.get("/reports", authMiddleware, async (req, res) => {
  try {
    const currentUser = await User.findOne({ id: req.user.id }).lean();
    if (!currentUser)
      return res.status(404).json({ error: "User not found" });

    const isAdmin =
      ADMIN_EMAIL &&
      currentUser.email?.toLowerCase() === ADMIN_EMAIL.toLowerCase();

    const ownOnly = !isAdmin || !("all" in req.query);

    const query = ownOnly ? { from: req.user.id } : {};
    const reports = await ReportModel.find(query).sort({ createdAt: -1 }).lean();

    // Fetch involved users for decoration
    const userIds = [
      ...new Set(reports.flatMap((r) => [r.from, r.targetId])),
    ];
    const users = await User.find({ id: { $in: userIds } }).lean();
    const userMap = new Map(users.map((u) => [u.id, baseSanitizeUser(u)]));

    const decorated = reports.map((r) => ({
      ...r,
      fromUser: userMap.get(r.from) || null,
      targetUser: userMap.get(r.targetId) || null,
    }));

    res.json({ reports: decorated, admin: isAdmin });
  } catch (err) {
    console.error("❌ GET /reports error:", err);
    res.status(500).json({ error: "Failed to load reports" });
  }
});

module.exports = router;
