/**
 * ============================================================
 * 📁 File: config/security.js
 * 🔒 Purpose: Centralizes all Express security middleware setup.
 *
 * Description:
 *   - This module applies HTTP security headers using Helmet.
 *   - It disables two specific restrictive policies
 *     (Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy)
 *     that can interfere with media uploads and embedded resources
 *     in RomBuzz (like Cloudinary images, videos, and WebSocket connections).
 *   - Designed to be imported and called from index.js for a clean setup.
 *
 * Usage:
 *   const { setupSecurity } = require("./config/security");
 *   setupSecurity(app);
 *
 * Dependencies:
 *   - helmet (npm install helmet)
 *
 * Notes:
 *   - Keep this module minimal and declarative.
 *   - Future additions like rate-limiting, CSP, or XSS protection
 *     can also be centralized here.
 * ============================================================
 */

const helmet = require("helmet");

/**
 * Applies core security middleware (Helmet) to the given Express app.
 * @param {Express.Application} app - The Express instance
 */
function setupSecurity(app) {
  // 🧱 Apply default Helmet protections
app.use(
  helmet({
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

console.log("🔐 Helmet security initialized successfully");


  console.log("🔐 Helmet security initialized successfully");
}

module.exports = { setupSecurity };
