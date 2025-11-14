/**
 * ============================================================
 * 📁 File: routes/aiWingman.js
 * 🧠 Purpose: Generate AI-based dating chat suggestions & rewrites.
 *
 * Endpoints:
 *   POST /api/ai/wingman/suggest  → Suggest icebreakers or openers
 *   POST /api/ai/wingman/rewrite  → Rewrite a given text in selected tone
 *
 * Features:
 *   - Integrates OpenAI GPT-4o-mini for realistic, empathetic suggestions
 *   - Falls back to mock messages when AI or API key is disabled
 *   - Supports multiple tones: funny, flirty, casual, friendly, polite, poetic
 *   - Safe default outputs even if API fails
 *
 * Dependencies:
 *   - authMiddleware.js → Validates JWT
 *   - LowDB instance (db.lowdb.js)
 *   - process.env.OPENAI_API_KEY
 *   - ENABLE_AI_WINGMAN env flag
 *
 * Notes:
 *   - Used by AI Wingman feature in ChatWindow and Discover pages
 *   - Modular and future-ready for fine-tuned AI models
 * ============================================================
 */

const express = require("express");
const router = express.Router();
const fetch = require("node-fetch");
const authMiddleware = require("../routes/auth-middleware");

const ENABLE_AI_WINGMAN = process.env.ENABLE_AI_WINGMAN === "true";

/* ======================
   🧩 Call OpenAI API
====================== */
async function callOpenAI(prompt, system) {
  if (!ENABLE_AI_WINGMAN || !process.env.OPENAI_API_KEY) {
    const err = new Error("AI disabled");
    err.code = "AI_DISABLED";
    throw err;
  }
  if (typeof fetch !== "function") {
    const err = new Error("fetch not available in this Node environment");
    err.code = "NO_FETCH";
    throw err;
  }

  const body = {
    model: "gpt-4o-mini",
    messages: [
      system ? { role: "system", content: system } : null,
      { role: "user", content: prompt },
    ].filter(Boolean),
    temperature: 0.7,
  };

  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`OpenAI error: ${resp.status} ${t}`);
  }

  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() || "";
}

/* ======================
   💬 Suggest Openers
====================== */
router.post("/ai/wingman/suggest", authMiddleware, async (req, res) => {
  const {
    myProfileSummary = "",
    theirProfileSummary = "",
    style = "friendly",
  } = req.body || {};

  try {
    if (!ENABLE_AI_WINGMAN || !process.env.OPENAI_API_KEY) {
      const examples = {
        funny: [
          "Are you made of copper and tellurium? Because you're Cu-Te 😄",
          "I was today years old when I realized I should message you.",
          "Quick question — coffee or chaotic first date?",
        ],
        polite: [
          "Hi! I really liked your profile — it feels warm and genuine.",
          "Hey there! How’s your day going?",
          "I’d love to know what makes you smile the most.",
        ],
        flirty: [
          "I was going to wait… but you seem worth breaking the ice for 😉",
          "Your smile might be my new favorite notification.",
          "Is it me, or did the room just get warmer?",
        ],
        casual: [
          "Hey, what’s up?",
          "How’s your week going?",
          "You seem cool — what kind of music are you into?",
        ],
        friendly: [
          "Hey! You seem like someone fun to talk to 😊",
          "Hi! What’s one thing that always makes you laugh?",
          "I liked your vibe — mind if we chat?",
        ],
      };
      return res.json({ suggestions: examples[style] || examples.friendly });
    }

    const system = `You are an empathetic dating wingman. Provide 3 short openers tailored to the other person's profile. Style=${style}.`;
    const prompt = `My profile: ${myProfileSummary}\nTheir profile: ${theirProfileSummary}\nGive 3 different one-liner openers. Number them.`;

    const text = await callOpenAI(prompt, system);
    const suggestions = text
      .split(/\n+/)
      .map((s) => s.replace(/^\d+[\).\s-]?\s*/, ""))
      .filter(Boolean)
      .slice(0, 3);

    res.json({ suggestions: suggestions.length ? suggestions : [text] });
  } catch (e) {
    if (e.code === "AI_DISABLED")
      return res.status(503).json({ error: "AI disabled" });
    console.error(e);
    res.status(500).json({ error: "AI error" });
  }
});

/* ======================
   ✍️ Rewrite a Message
====================== */
router.post("/ai/wingman/rewrite", authMiddleware, async (req, res) => {
  const { text = "", tone = "friendly" } = req.body || {};

  try {
    if (!ENABLE_AI_WINGMAN || !process.env.OPENAI_API_KEY) {
      const mock = {
        friendly: `Friendly and open-minded person who loves meaningful conversations and cozy evenings ✨`,
        confident: `Confident, curious, and ready to explore new connections 💫`,
        funny: `Professional overthinker who still believes in good coffee and bad jokes ☕😂`,
        poetic: `A heart full of sunsets, words, and wonder 🌅`,
      };
      return res.json({ rewrite: mock[tone] || mock.friendly });
    }

    const system = `Rewrite messages for dating chat. Keep it short, warm, and natural. Tone=${tone}.`;
    const prompt = `Rewrite this, same intent, improved tone:\n"${text}"`;

    const out = await callOpenAI(prompt, system);
    res.json({ rewrite: out });
  } catch (e) {
    if (e.code === "AI_DISABLED")
      return res.status(503).json({ error: "AI disabled" });
    console.error(e);
    res.status(500).json({ error: "AI error" });
  }
});

module.exports = router;
