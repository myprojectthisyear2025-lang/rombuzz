import React, { useState } from "react";
import { FaTimes, FaImage, FaVideo, FaClock, FaGlobe, FaUserFriends, FaLock } from "react-icons/fa";

const API_BASE = "http://localhost:4000/api";

export default function CreatePostModal({ onClose, onPostCreated, token }) {
  const [text, setText] = useState("");
  const [mediaUrl, setMediaUrl] = useState("");
  const [type, setType] = useState("text");
  const [privacy, setPrivacy] = useState("matches");
  const [expiresIn, setExpiresIn] = useState(24); // hours
  const [uploading, setUploading] = useState(false);
  const [tags, setTags] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!text.trim() && !mediaUrl) return;

    try {
      const postData = {
        text: text.trim(),
        mediaUrl,
        type,
        privacy,
        tags: tags.split(",").map(tag => tag.trim()).filter(Boolean),
      };

      if (type === "story") {
        postData.expiresAt = Date.now() + (expiresIn * 60 * 60 * 1000);
      }

      const res = await fetch(`${API_BASE}/buzz/posts`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(postData),
      });

      if (res.ok) {
        onPostCreated();
      }
    } catch (err) {
      console.error("Create post error:", err);
    }
  };

  const handleMediaUpload = async (file) => {
    setUploading(true);
    try {
      // Simulate upload - replace with actual Cloudinary upload
      const formData = new FormData();
      formData.append("file", file);
      
      // This would be your actual upload endpoint
      const uploadRes = await fetch(`${API_BASE}/upload-media`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      
      const data = await uploadRes.json();
      setMediaUrl(data.url);
    } catch (err) {
      console.error("Upload error:", err);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl w-full max-w-md max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-lg font-semibold">Create Buzz</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <FaTimes />
          </button>
        </div>

        {/* Content */}
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {/* Post Type Selection */}
          <div className="flex gap-2">
            {[
              { value: "text", icon: "📝", label: "Text" },
              { value: "photo", icon: "🖼️", label: "Photo" },
              { value: "reel", icon: "🎬", label: "Reel" },
              { value: "story", icon: "📖", label: "Story" },
            ].map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => setType(option.value)}
                className={`flex-1 py-2 rounded-lg border-2 transition ${
                  type === option.value
                    ? "border-pink-500 bg-pink-50 text-pink-600"
                    : "border-gray-200 text-gray-600 hover:border-pink-300"
                }`}
              >
                <span className="text-lg block mb-1">{option.icon}</span>
                <span className="text-xs">{option.label}</span>
              </button>
            ))}
          </div>

          {/* Text Input */}
          <textarea
            placeholder="What's buzzing? Share with your matches..."
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full border border-gray-300 rounded-lg p-3 resize-none focus:border-pink-500 focus:ring-1 focus:ring-pink-500"
            rows={4}
          />

          {/* Media Upload */}
          {(type === "photo" || type === "reel") && (
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 text-center">
              <input
                type="file"
                accept={type === "photo" ? "image/*" : "video/*"}
                onChange={(e) => handleMediaUpload(e.target.files[0])}
                className="hidden"
                id="media-upload"
              />
              <label
                htmlFor="media-upload"
                className="cursor-pointer block"
              >
                <FaImage className="text-3xl text-gray-400 mx-auto mb-2" />
                <p className="text-gray-600">
                  {uploading ? "Uploading..." : `Click to upload ${type === "photo" ? "photo" : "video"}`}
                </p>
              </label>
              {mediaUrl && (
                <div className="mt-2">
                  <img src={mediaUrl} alt="Preview" className="max-h-32 mx-auto rounded" />
                </div>
              )}
            </div>
          )}

          {/* Story Expiration */}
          {type === "story" && (
            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm text-gray-600">
                <FaClock />
                Expires in:
              </label>
              <select
                value={expiresIn}
                onChange={(e) => setExpiresIn(Number(e.target.value))}
                className="w-full border border-gray-300 rounded-lg p-2"
              >
                <option value={6}>6 hours</option>
                <option value={12}>12 hours</option>
                <option value={24}>24 hours</option>
                <option value={48}>48 hours</option>
              </select>
            </div>
          )}

          {/* Privacy Settings */}
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm text-gray-600">
              <FaLock />
              Privacy:
            </label>
            <select
              value={privacy}
              onChange={(e) => setPrivacy(e.target.value)}
              className="w-full border border-gray-300 rounded-lg p-2"
            >
              <option value="matches">All Matches</option>
              <option value="public">Public</option>
              <option value="specific">Specific Matches</option>
            </select>
          </div>

          {/* Tags */}
          <div className="space-y-2">
            <label className="text-sm text-gray-600">Tags (comma separated):</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="fun, dating, love"
              className="w-full border border-gray-300 rounded-lg p-2 text-sm"
            />
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 py-2 border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!text.trim() && !mediaUrl}
              className="flex-1 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              Buzz It! 🐝
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}