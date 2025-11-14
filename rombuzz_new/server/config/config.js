/**
 * ============================================================
 * 📁 File: config/config.js
 * 🧩 Purpose: Centralized global configuration for RomBuzz.
 *
 * Features:
 *   - Loads environment variables via dotenv
 *   - Initializes Google OAuth2Client for Google login/signup
 *   - Exports feature toggles (blurred profiles, restricted views, etc.)
 *
 * Exports:
 *   - googleClient → OAuth2Client instance using GOOGLE_CLIENT_ID
 *   - FEATURE_TOGGLES → Object containing frontend/backend switches
 *
 * Example Toggles:
 *   ENABLE_BLURRED_PROFILES: true
 *   SHOW_PRIVATE: true
 *   SHOW_RESTRICTED: false
 *
 * Notes:
 *   - Used in all auth-related routes and global startup config
 *   - Keep all environment-dependent constants here
 * ============================================================
 */

require("dotenv").config();

// ✅ Import Google OAuth2 client locally (so it doesn’t rely on index.js)
const { OAuth2Client } = require("google-auth-library");

// Create the client using your env variable
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ✅ Example feature toggles and constants
const FEATURE_TOGGLES = {
  ENABLE_BLURRED_PROFILES: true,
  SHOW_PRIVATE: true,
  SHOW_RESTRICTED: false,
};

// Export everything you might reuse later
module.exports = {
  googleClient,
  FEATURE_TOGGLES,
};
