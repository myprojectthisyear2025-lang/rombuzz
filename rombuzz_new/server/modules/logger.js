/**
 * ============================================================
 * 📁 File: modules/logger.js
 * 🧩 Purpose: Unified color-coded console logger for RomBuzz
 *
 * Exports:
 *   - logInfo(msg)
 *   - logSuccess(msg)
 *   - logWarn(msg)
 *   - logError(msg)
 *   - logSocket(event, data)
 *
 * Features:
 *   - Uses Chalk (v5+) dynamic import for ESM compatibility
 *   - Consistent timestamps for all log entries
 *   - Lightweight and readable output for dev/production
 * ============================================================
 */

let chalk; // dynamically import to support ESM-only module

(async () => {
  const chalkModule = await import("chalk");
  chalk = chalkModule.default;
})();

function time() {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

// 🧩 Log helpers
function logInfo(...msg) {
  console.log(chalk?.cyan?.(`[INFO ${time()}]`) || "[INFO]", ...msg);
}

function logSuccess(...msg) {
  console.log(chalk?.green?.(`[SUCCESS ${time()}]`) || "[SUCCESS]", ...msg);
}

function logWarn(...msg) {
  console.log(chalk?.yellow?.(`[WARN ${time()}]`) || "[WARN]", ...msg);
}

function logError(...msg) {
  console.error(chalk?.red?.(`[ERROR ${time()}]`) || "[ERROR]", ...msg);
}

function logSocket(event, data) {
  console.log(chalk?.magenta?.(`[SOCKET ${time()}]`) || "[SOCKET]", event, data || "");
}

module.exports = {
  logInfo,
  logSuccess,
  logWarn,
  logError,
  logSocket,
};
