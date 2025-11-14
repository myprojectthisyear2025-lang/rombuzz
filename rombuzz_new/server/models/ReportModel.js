/**
 * ============================================================
 * 📁 File: models/ReportModel.js
 * 💾 Purpose: Stores user reports and moderation outcomes.
 * ============================================================
 */
const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true, index: true },
    from: { type: String, required: true, index: true },
    targetId: { type: String, required: true, index: true },
    reason: { type: String, required: true },
    status: {
      type: String,
      enum: ["open", "reviewed", "dismissed", "actioned"],
      default: "open",
    },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.ReportModel ||
  mongoose.model("ReportModel", reportSchema);
