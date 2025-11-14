/**
 * ======================================================================
 * 📁 File: utils/jwt.js
 * 💡 Purpose:
 *   Centralizes JSON Web Token signing and verification helpers for RomBuzz.
 *   Keeps sensitive signing logic out of index.js.
 *
 * ✅ Exact behavior as your old inline code:
 *   - Uses same payload { id, email }
 *   - Uses same JWT_SECRET and TOKEN_EXPIRES_IN
 *
 * Exports:
 *   - signToken(user, JWT_SECRET, TOKEN_EXPIRES_IN)
 *
 * Optional future additions:
 *   - verifyToken(token, JWT_SECRET)
 *   - decodeToken(token)
 * ======================================================================
 */

const jwt = require("jsonwebtoken");

/**
 * 🔐 signToken(user, secret, expiresIn)
 * Creates a JWT for the given user.
 *
 * @param {object} user  – must contain { id, email }
 * @param {string} secret – JWT secret key
 * @param {string|number} expiresIn – token expiration (e.g. '30d')
 * @returns {string} signed JWT
 */
function signToken(user, secret, expiresIn) {
  return jwt.sign(
    { id: user.id, email: user.email },
    secret,
    { expiresIn }
  );
}

module.exports = { signToken };
