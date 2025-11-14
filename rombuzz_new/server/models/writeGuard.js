/**
 * ============================================================
 * 📁 File: models/writeGuard.js
 * 🧩 Purpose: Prevents LowDB write errors caused by file-lock issues
 *             (EPERM / EBUSY) on Windows environments.
 *
 * Features:
 *   - Adds queued write protection for all db.write() calls
 *   - Retries failed writes with exponential backoff (50–300ms)
 *   - Ensures single writer access via Promise chaining
 *
 * Dependencies:
 *   - db.lowdb.js → Base LowDB instance
 *
 * Notes:
 *   - Automatically patched into db.write() on server start
 *   - Logs “🧩 Write guard applied to LowDB instance” on success
 *   - Prevents crashes from concurrent or delayed writes on Windows
 * ============================================================
 */

// =======================
// GLOBAL WRITE GUARD FOR WINDOWS EPERM
// =======================
// 🧹 Global Write Guard for LowDB (fixes EPERM/EBUSY on Windows)

module.exports = function applyWriteGuard(db) {
  const _rawWrite = db.write.bind(db);
  let _writeQueue = Promise.resolve();

  async function writeWithRetry() {
    _writeQueue = _writeQueue.then(async () => {
      const MAX_TRIES = 6; // ~ cumulative ~1s backoff
      let attempt = 0;
      while (true) {
        try {
          await _rawWrite();
          return;
        } catch (err) {
          const code = err && err.code;
          if (code === "EPERM" || code === "EBUSY") {
            attempt++;
            if (attempt >= MAX_TRIES) throw err;
            const delay = 50 * attempt; // exponential-ish backoff
            await new Promise((r) => setTimeout(r, delay));
            continue;
          }
          throw err; // rethrow other errors
        }
      }
    });
    return _writeQueue;
  }

  // Monkey-patch db.write globally
  db.write = writeWithRetry;

  console.log("🧩 Write guard applied to LowDB instance");
};
