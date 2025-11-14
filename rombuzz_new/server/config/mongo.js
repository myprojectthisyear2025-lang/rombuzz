// /config/mongo.js
// Centralized Mongoose connection for RomBuzz backend

const mongoose = require("mongoose");

let isConnecting = false;

async function connectMongo({
  uri = process.env.MONGO_URI,
  dbName = process.env.MONGO_DB_NAME || "rombuzz",
} = {}) {
  if (!uri) {
    console.warn("[mongo] MONGO_URI is not set. Skipping Mongo connection.");
    return null;
  }

  if (mongoose.connection.readyState === 1) return mongoose.connection;
  if (isConnecting) return mongoose.connection;

  isConnecting = true;

  mongoose.set("strictQuery", true);
  mongoose.set("debug", process.env.MONGO_DEBUG === "true");

  try {
    await mongoose.connect(uri, {
      dbName,
      maxPoolSize: Number(process.env.MONGO_POOL_MAX || 20),
      minPoolSize: Number(process.env.MONGO_POOL_MIN || 2),
      maxIdleTimeMS: Number(process.env.MONGO_MAX_IDLE_MS || 300000),
      serverSelectionTimeoutMS: Number(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || 10000),
      socketTimeoutMS: Number(process.env.MONGO_SOCKET_TIMEOUT_MS || 45000),
    });

    console.log(`[mongo] Connected to "${dbName}" ✅`);
    wireConnectionLogging();
    isConnecting = false;
    return mongoose.connection;
  } catch (err) {
    isConnecting = false;
    console.error("[mongo] connection error:", err.message);
    throw err;
  }
}

function wireConnectionLogging() {
  const conn = mongoose.connection;
  if (conn._loggingWired) return;
  conn._loggingWired = true;

  conn.on("connected", () => console.log("[mongo] connected"));
  conn.on("error", (err) => console.error("[mongo] error:", err.message));
  conn.on("disconnected", () => console.warn("[mongo] disconnected"));
  process.on("SIGINT", async () => {
    await conn.close();
    console.log("[mongo] closed on SIGINT");
    process.exit(0);
  });
}

async function healthCheckMongo() {
  const conn = mongoose.connection;
  let pingOk = false;
  if (conn.readyState === 1) {
    try {
      await conn.db.command({ ping: 1 });
      pingOk = true;
    } catch (_) {}
  }
  return {
    connected: conn.readyState === 1,
    dbName: conn.name,
    host: conn.host,
    pingOk,
  };
}

module.exports = { connectMongo, healthCheckMongo };
