// server/config/multer.js
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  },
});

// ~25 MB cap; tweak if you need larger video uploads
const limits = { fileSize: 25 * 1024 * 1024 };

module.exports = multer({ storage, limits });
