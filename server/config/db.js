// server/config/db.js
const { MongoClient } = require("mongodb");

const uri = process.env.MONGO_URI;
if (!uri) {
  console.error("❌ MONGO_URI is missing. Set it in Render > Environment.");
  process.exit(1);
}

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

let db;
let users, posts, likes, matches, notifications, messages, blocks, reports, roomMessages, matchStreaks;

async function connectMongo() {
  if (db) return db; // already connected
  await client.connect();
  db = client.db("rombuzz");

  // collections
  users = db.collection("users");
  posts = db.collection("posts");
  likes = db.collection("likes");
  matches = db.collection("matches");
  notifications = db.collection("notifications");
  messages = db.collection("messages");
  blocks = db.collection("blocks");
  reports = db.collection("reports");
  roomMessages = db.collection("roomMessages");
  matchStreaks = db.collection("matchStreaks");

  console.log("✅ Connected to MongoDB Atlas (DB: rombuzz)");
  return db;
}

module.exports = {
  connectMongo,
  get db() { return db; },
  get users() { return users; },
  get posts() { return posts; },
  get likes() { return likes; },
  get matches() { return matches; },
  get notifications() { return notifications; },
  get messages() { return messages; },
  get blocks() { return blocks; },
  get reports() { return reports; },
  get roomMessages() { return roomMessages; },
  get matchStreaks() { return matchStreaks; },
};
