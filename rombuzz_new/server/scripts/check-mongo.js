// /scripts/check-mongo.js
// Quick MongoDB connectivity test for RomBuzz backend.

require("dotenv").config();
const { connectMongo, healthCheckMongo } = require("../config/mongo");

(async () => {
  try {
    await connectMongo();
    const status = await healthCheckMongo();
    console.log("Mongo Health:", status);
    process.exit(status.connected && status.pingOk ? 0 : 2);
  } catch (err) {
    console.error("Mongo connection failed:", err?.message || err);
    process.exit(1);
  }
})();
