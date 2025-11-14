/**
 * ============================================================
 * 📁 File: config/env.js
 * ⚙️ Purpose: Centralized environment constants & server defaults
 *
 * Exports:
 *   - PORT
 *   - JWT_SECRET
 *   - TOKEN_EXPIRES_IN
 *   - ADMIN_EMAIL
 *   - OBFUSCATION_MIN_METERS
 *   - OBFUSCATION_MAX_METERS
 *   - SHOW_PRIVATE
 *   - SHOW_RESTRICTED
 *
 * Notes:
 *   - Keeps all environment-dependent constants in one place.
 *   - Simplifies production / local configuration.
 * ============================================================
 */

require("dotenv").config();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "rom_seed_dev_change_me";
const TOKEN_EXPIRES_IN = process.env.TOKEN_EXPIRES_IN || "30d";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";

const OBFUSCATION_MIN_METERS = Number(process.env.OBFUSCATION_MIN_METERS || 50);
const OBFUSCATION_MAX_METERS = Number(process.env.OBFUSCATION_MAX_METERS || 200);

const SHOW_PRIVATE = String(process.env.SHOW_PRIVATE || "true") === "true";
const SHOW_RESTRICTED = String(process.env.SHOW_RESTRICTED || "false") === "true";

module.exports = {
  PORT,
  JWT_SECRET,
  TOKEN_EXPIRES_IN,
  ADMIN_EMAIL,
  OBFUSCATION_MIN_METERS,
  OBFUSCATION_MAX_METERS,
  SHOW_PRIVATE,
  SHOW_RESTRICTED,

  // Mongo (optional exports)
  MONGO_URI: process.env.MONGO_URI || "",
  MONGO_DB_NAME: process.env.MONGO_DB_NAME || "rombuzz",
};

