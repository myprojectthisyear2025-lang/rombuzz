/**
 * ============================================================
 * 📁 File: modules/mongoInit.js
 * 💾 Purpose: Initialize MongoDB (Mongoose) connection in parallel
 *             with existing LowDB database, non-blocking and safe.
 * ============================================================
 */

const { connectMongo, healthCheckMongo } = require("../config/mongo");
const { logSuccess, logWarn, logError } = require("./logger");

async function initMongo() {
  try {
    await connectMongo();
    const health = await healthCheckMongo();

    if (health.connected && health.pingOk) {
      logSuccess(`✅ MongoDB connected (${health.dbName}@${health.host})`);
    } else {
      logWarn("⚠️ MongoDB ping or connection not healthy yet");
    }
  } catch (err) {
    logError("❌ MongoDB connection failed:", err.message || err);
  }
}

module.exports = { initMongo };
