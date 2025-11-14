/**
 * ============================================================
 * 📁 File: modules/userSync.js
 * 🔄 Purpose: Sync LowDB users into MongoDB User collection
 * ============================================================
 */

const User = require("../models/User");
const { logInfo, logWarn, logError, logSuccess } = require("./logger");

/**
 * Sync a single user object from LowDB into MongoDB.
 * - Creates or updates the corresponding Mongo document.
 * - Safe to call after any user registration/update.
 */
async function syncUserToMongo(lowUser) {
  try {
    if (!lowUser?.email || !lowUser?.id) return;

    const existing = await User.findOne({ id: lowUser.id });
    if (existing) {
      await User.updateOne(
        { id: lowUser.id },
        { $set: { ...lowUser, updatedAt: new Date() } }
      );
      logInfo(`🔁 Synced user update → Mongo: ${lowUser.email}`);
    } else {
      await User.create({ ...lowUser });
      logInfo(`🆕 Synced new user → Mongo: ${lowUser.email}`);
    }
  } catch (err) {
    logError("❌ User sync failed:", err.message || err);
  }
}

/**
 * Bulk sync all LowDB users once (optional startup utility).
 */
async function bulkSyncAllUsers(lowUsers = []) {
  if (!Array.isArray(lowUsers) || !lowUsers.length) return;
  logWarn(`⚙️  Bulk syncing ${lowUsers.length} users → Mongo...`);
  for (const u of lowUsers) {
    await syncUserToMongo(u);
  }
  logSuccess("✅ Bulk sync complete");
}

module.exports = { syncUserToMongo, bulkSyncAllUsers };
