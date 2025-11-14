/**
 * ============================================================
 * 📁 File: routes/settings.js
 * 🧩 Purpose: Manages per-user app preferences and discovery settings.
 *
 * Endpoints:
 *   GET  /api/settings      → Fetch current user's saved settings
 *   PUT  /api/settings      → Update settings (theme, visibility, wingman prefs)
 *
 * Features:
 *   - Fully migrated to MongoDB (via User model)
 *   - Maintains unified DEFAULT_SETTINGS structure
 *   - Supports nested merges for `notifications` and `wingman`
 *   - Stores discover visibility, blur preference, and distance units
 *   - Allows multilingual and radius customization
 *   - Auto-creates settings object for new users if absent
 *
 * Dependencies:
 *   - models/User.js        → MongoDB user model
 *   - auth-middleware.js    → JWT-based authentication
 *
 * Notes:
 *   - Used by Settings.jsx and Discover.jsx
 *   - Returns merged settings (default + user overrides)
 *   - Safe to extend with additional feature toggles
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const authMiddleware = require("./auth-middleware");
const User = require("../models/User");

// =======================
// ⚙️ DEFAULT SETTINGS
// =======================
const DEFAULT_SETTINGS = {
  discoverVisible: true,      // show me in Discover
  blurDefault: true,          // blur my profile by default
  showLastSeen: true,         // show last active
  incognitoMode: false,       // temporary hide
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

/* ============================================================
   ✅ GET /api/settings
   Fetch current user's settings (merged with defaults)
============================================================ */
router.get("/", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id }).lean();
    if (!user) return res.status(404).json({ error: "User not found" });

    const settings = { ...DEFAULT_SETTINGS, ...(user.settings || {}) };
    res.json({ settings });
  } catch (err) {
    console.error("❌ GET /settings error:", err);
    res.status(500).json({ error: "Failed to load settings" });
  }
});

/* ============================================================
   ✅ PUT /api/settings
   Update current user's settings
============================================================ */
router.put("/", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id });
    if (!user) return res.status(404).json({ error: "User not found" });

    const body = req.body || {};
    const prev = user.settings || {};
    const next = { ...DEFAULT_SETTINGS, ...prev };

    // 🔧 Simple keys
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

    // 🔔 Nested: notifications
    if (body.notifications && typeof body.notifications === "object") {
      next.notifications = {
        ...DEFAULT_SETTINGS.notifications,
        ...next.notifications,
        ...body.notifications,
      };
    }

    // 💬 Nested: wingman
    if (body.wingman && typeof body.wingman === "object") {
      next.wingman = {
        ...DEFAULT_SETTINGS.wingman,
        ...next.wingman,
        ...body.wingman,
      };
    }

    // 💾 Save updated settings
    user.settings = next;
    await user.save();

    res.json({ settings: next });
  } catch (err) {
    console.error("❌ PUT /settings error:", err);
    res.status(500).json({ error: "Failed to update settings" });
  }
});

module.exports = router;
