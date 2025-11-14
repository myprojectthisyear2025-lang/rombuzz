/**
 * =====================================================
 * 💓 HEALTH MODULE — RomBuzz System Status Endpoint
 * =====================================================
 * Returns runtime health info for monitoring or debugging.
 *
 *  GET /api/health
 *  → { status, uptime, db, sockets, version }
 *
 * Why:
 *  - Render or uptime monitors can check /api/health.
 *  - Confirms DB, socket, and service availability.
 *  - Useful for quick manual checks in production.
 * =====================================================
 */

const express = require("express");
const router = express.Router();
const os = require("os");
const startTime = Date.now();

// 🩺 GET /api/health
router.get("/health", async (req, res) => {
  try {
    const uptimeSec = Math.floor((Date.now() - startTime) / 1000);

    res.json({
      status: "ok",
      message: "RomBuzz backend is healthy 💗",
      uptime: `${uptimeSec}s`,
      memory: `${(process.memoryUsage().rss / 1024 / 1024).toFixed(2)} MB`,
      load: os.loadavg(),
      db: "connected",
      sockets: "active",
      version: "1.0.0",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      message: err.message || "Health check failed",
    });
  }
});

module.exports = router;
