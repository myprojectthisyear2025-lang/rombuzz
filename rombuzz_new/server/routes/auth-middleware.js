
/**
 * ============================================================
 * 📁 File: routes/auth-middleware.js
 * 🧩 Purpose: Express middleware that authenticates requests via JWT.
 *
 * Behavior:
 *   - Reads the Authorization header: "Bearer <token>"
 *   - Verifies the JWT using process.env.JWT_SECRET
 *   - On success: attaches { id, email } to req.user and calls next()
 *   - On failure: returns 401 (missing, invalid, or expired token)
 *
 * Dependencies:
 *   - jsonwebtoken (jwt)
 *   - process.env.JWT_SECRET
 *
 * Notes:
 *   - Used by protected routes across /routes (users, profile, buzz, etc.)
 *   - Keep responses minimal to avoid leaking token parsing details
 *   - Works the same in LowDB now and Mongoose later (no changes needed)
 * ============================================================
 */

// =======================
// AUTH MIDDLEWARE
// =======================
// 🔐 Auth middleware for verifying JWT tokens

const jwt = require("jsonwebtoken");

module.exports = function authMiddleware(req, res, next) {
  const JWT_SECRET = process.env.JWT_SECRET || "rom_seed_dev_change_me";
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded?.id) {
      return res.status(401).json({ error: "Invalid token structure" });
    }
    req.user = { id: decoded.id, email: decoded.email };
    return next();
  } catch (err) {
    console.error("Auth middleware error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

