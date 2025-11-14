/**
 * ============================================================
 * 📁 File: routes/debug.js
 * 🧩 Purpose: Developer-only debugging routes for RomBuzz backend.
 *
 * Endpoints:
 *   GET /api/debug/users   → Lists all registered users (sanitized)
 *
 * Features:
 *   - Reads from LowDB and returns minimal account info for inspection
 *   - Useful for verifying signup methods, password hashes, and account creation
 *   - Helps detect legacy accounts that may need migration (e.g., old "password" fields)
 *
 * ⚠️ Security Notice:
 *   This route should ONLY be used in a safe environment (development or admin-protected)
 *   Never expose this endpoint publicly on production without authentication or IP restriction.
 *
 * Dependencies:
 *   - db.lowdb.js         → Access to RomBuzz user database
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const User = require("../models/User"); // ✅ Use Mongoose User model

/* ============================================================
   🧠 GET /api/debug/users
   ------------------------------------------------------------
   Returns a sanitized list of all user accounts with diagnostic info:
   - ID and email
   - Whether a passwordHash or legacy password exists
   - Length of hash (for sanity check)
   - Signup method (direct vs. Google)
   - Account creation timestamp
============================================================ */
router.get("/debug/users", async (req, res) => {
  try {
    const users = await User.find({}, {
      id: 1,
      email: 1,
      passwordHash: 1,
      password: 1,
      createdAt: 1,
      googleId: 1,
      _id: 0,
    }).lean();

    res.json({
      users: users.map((u) => ({
        id: u.id,
        email: u.email,
        hasPasswordHash: !!u.passwordHash,
        passwordHashLength: u.passwordHash ? u.passwordHash.length : 0,
        hasLegacyPassword: !!u.password,
        signupMethod: u.passwordHash ? "direct" : (u.googleId ? "google" : "unknown"),
        createdAt: u.createdAt,
      })),
    });
  } catch (err) {
    console.error("❌ Debug users fetch error:", err);
    res.status(500).json({ error: "Failed to load user list" });
  }
});

console.log("✅ Debug routes initialized (MongoDB)");

module.exports = router;
