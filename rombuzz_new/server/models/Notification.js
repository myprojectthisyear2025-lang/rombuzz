/**
 * ============================================================
 * 📁 File: models/Notification.js
 * 💾 Purpose: Mongoose schema for user notifications
 *
 * Description:
 *   Stores all system, match, buzz, like, and AI Wingman alerts.
 *   Fully mirrors the old LowDB structure for a seamless migration.
 *
 * Used in:
 *   - routes/notifications.js
 *   - utils/helpers.js → sendNotification()
 * ============================================================
 */

const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true }, // shortid-compatible
    toId: { type: String, required: true, index: true }, // recipient user
    fromId: { type: String, default: "" }, // sender (userId or "system")
    type: {
      type: String,
      enum: [
        "wingman",
        "match",
        "buzz",
        "like",
        "comment",
        "reaction",
        "new_post",
        "share",
        "system",
      ],
      default: "system",
    },
    message: { type: String, required: true },
    href: { type: String, default: "" },
    postId: { type: String, default: "" },
    postOwnerId: { type: String, default: "" },
    entity: { type: String, default: "" },
    entityId: { type: String, default: "" },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.Notification || mongoose.model("Notification", notificationSchema);
