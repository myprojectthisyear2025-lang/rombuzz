/**
 * ============================================================
 * 📁 File: config/cors.js
 * 🧩 Purpose: Defines and applies CORS (Cross-Origin Resource Sharing)
 *             rules for RomBuzz API across all environments.
 *
 * Features:
 *   - Allows requests only from approved frontend domains
 *   - Supports localhost & production (rombuzz.com / vercel.app)
 *   - Handles OPTIONS preflight for all routes (Express 5+ compatible)
 *
 * Behavior:
 *   - Dynamically checks the request's origin against allowedOrigins[]
 *   - Permits requests without origin (mobile apps, curl, etc.)
 *   - Enables credentialed requests (cookies / auth headers)
 *
 * Used In:
 *   - index.js → setupCors(app);
 *
 * Notes:
 *   - Update allowedOrigins[] whenever adding new frontend URLs
 *   - Always keep OPTIONS preflight handler below the CORS middleware
 * ============================================================
 */

// =======================
// CORS CONFIG (CLEAN, UNIFIED)
// =======================
// ✅ Clean, self-contained CORS setup for RomBuzz
const cors = require("cors");

const allowedOrigins = [
  "https://rombuzz.com",
  "https://www.rombuzz.com",
  "https://rombuzz.vercel.app",
  "https://rombuzz-main.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173",
];

function setupCors(app) {
 app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS not allowed for this origin: " + origin));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Accept",
      "X-Requested-With",
      "Origin",
      "Sec-Fetch-Site",
      "Sec-Fetch-Mode",
      "Sec-Fetch-Dest",
    ],
    credentials: true,
    preflightContinue: false,
  })
);

// Still keep this for OPTIONS preflight
app.options(/.*/, cors());

}

module.exports = setupCors;


