/**
 * =====================================================
 * 🛡️ GLOBAL ERROR HANDLER
 * =====================================================
 * Intercepts all unhandled errors and sends consistent
 * JSON responses instead of crashing the server.
 *
 * Usage:
 *   const { errorHandler } = require("./modules/errorHandler");
 *   app.use(errorHandler);
 * =====================================================
 */

const { logError } = require("./logger");

function errorHandler(err, req, res, next) {
  // Log for server debugging
  logError(`[${req.method}] ${req.originalUrl} → ${err.message}`);

  // Send safe JSON response
  const status = err.status || 500;
  res.status(status).json({
    success: false,
    error: err.message || "Internal Server Error",
  });
}

module.exports = { errorHandler };
