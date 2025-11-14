/**
 * ============================================================
 * 📁 File: config/sendgrid.js
 * 🧩 Purpose: Configures SendGrid for transactional email delivery.
 *
 * Features:
 *   - Initializes SendGrid using SENDGRID_API_KEY from .env
 *   - Provides ready-to-use sgMail instance
 *   - Supports OTP verification, password resets, and alerts
 *
 * Environment Variables:
 *   SENDGRID_API_KEY
 *   FROM_EMAIL
 *
 * Used In:
 *   - /api/auth/send-code (email OTP)
 *   - /api/auth/forgot-password (reset code)
 *
 * Notes:
 *   - All SendGrid logic centralized here
 *   - Always check for key presence before sending emails
 * ============================================================
 */

// =======================
// FEATURE TOGGLES
// =======================

require("dotenv").config();
const { OAuth2Client } = require("google-auth-library");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Dynamically loaded feature toggles
const FEATURE_TOGGLES = {
  ENABLE_BLURRED_PROFILES: String(process.env.ENABLE_BLURRED_PROFILES || 'true') === 'true',
  ENABLE_LIKES_MATCHES:    String(process.env.ENABLE_LIKES_MATCHES || 'true') === 'true',
  ENABLE_REALTIME_CHAT:    String(process.env.ENABLE_REALTIME_CHAT || 'true') === 'true',
  ENABLE_AI_WINGMAN:       String(process.env.ENABLE_AI_WINGMAN || 'false') === 'true',
};

module.exports = {
  googleClient,
  FEATURE_TOGGLES,
};
