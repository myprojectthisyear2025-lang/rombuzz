/**
 * ============================================================
 * 📁 File: modules/system.js
 * 🧭 Purpose: Handles application startup logging & sanity checks
 *
 * Exports:
 *   - logStartupSummary()
 * ============================================================
 */

function logStartupSummary({ PORT, FEATURE_TOGGLES }) {
  console.log("\n🚀 Rombuzz Backend Boot Summary:");
  console.log("--------------------------------");
  console.log("🌐 Environment:", process.env.NODE_ENV || "development");
  console.log("📦 Port:", PORT);
  console.log("⚙️  Feature Toggles:", JSON.stringify(FEATURE_TOGGLES, null, 2));
  console.log("📡 API Base:", process.env.RENDER_EXTERNAL_URL || "local");
  console.log("--------------------------------\n");
}

module.exports = { logStartupSummary };
