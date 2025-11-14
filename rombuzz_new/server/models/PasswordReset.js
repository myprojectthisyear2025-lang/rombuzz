/**
 * ============================================================
 * 📁 File: models/PasswordReset.js
 * 🧩 Purpose: Temporary password reset codes for RomBuzz users.
 *
 * Schema:
 *   - email       → user email (lowercase)
 *   - code        → 6-digit verification code
 *   - expiresAt   → timestamp (10 min lifetime)
 *
 * Notes:
 *   - Each request overwrites previous one for same email.
 *   - Auto-expires handled manually during verification.
 * ============================================================
 */

const mongoose = require("mongoose");

const PasswordResetSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, index: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }, // ⏳ TTL auto-expiry
});


module.exports =
  mongoose.models.PasswordReset ||
  mongoose.model("PasswordReset", PasswordResetSchema);
