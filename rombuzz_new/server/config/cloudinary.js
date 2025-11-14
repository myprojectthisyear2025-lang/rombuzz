/**
 * ============================================================
 * 📁 File: config/cloudinary.js
 * 🧩 Purpose: Configures and initializes Cloudinary for image uploads.
 *
 * Features:
 *   - Loads credentials from environment variables (.env)
 *   - Provides centralized Cloudinary configuration
 *   - Used globally by upload routes (avatars, posts, stories, etc.)
 *
 * Environment Variables:
 *   CLOUDINARY_CLOUD_NAME
 *   CLOUDINARY_API_KEY
 *   CLOUDINARY_API_SECRET
 *
 * Used In:
 *   - index.js → cloudinary.config()
 *   - routes/upload.js (e.g., /api/upload-avatar, /api/upload-post)
 *
 * Notes:
 *   - Keep secrets in .env (never hardcode)
 *   - Always use secure URLs (https://res.cloudinary.com/...)
 * ============================================================
 */

// =======================
// CLOUDINARY CONFIG
// =======================

require("dotenv").config();
const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

module.exports = cloudinary;


