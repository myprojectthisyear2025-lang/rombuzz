// src/pages/CompleteProfile.jsx
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

const CompleteProfile = ({ user, setUser }) => {
  const navigate = useNavigate();
  const [avatar, setAvatar] = useState(null);
  const [avatarPreview, setAvatarPreview] = useState("");
  const [photos, setPhotos] = useState([]);
  const [photoPreviews, setPhotoPreviews] = useState([]);
  const [hobbies, setHobbies] = useState("");
  const [matchPref, setMatchPref] = useState("any");
  const [locationRadius, setLocationRadius] = useState(10);
  const [ageRange, setAgeRange] = useState({ min: 20, max: 50 });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // handle avatar upload + preview
  const handleAvatarChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setAvatar(file);
      setAvatarPreview(URL.createObjectURL(file));
    }
  };

  // handle additional photo upload + previews
  const handlePhotosChange = (e) => {
    const files = Array.from(e.target.files);
    setPhotos(files);
    const previews = files.map((f) => URL.createObjectURL(f));
    setPhotoPreviews(previews);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!avatar) return setError("Profile picture is required");
    setError("");
    setLoading(true);

    try {
      const token = localStorage.getItem("token");
      if (!token) {
        setError("You must be logged in to complete your profile");
        setLoading(false);
        return;
      }

      // Upload avatar
      const formData = new FormData();
      formData.append("avatar", avatar);
      const avatarRes = await fetch(`${API_BASE}/upload-avatar`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      if (!avatarRes.ok) throw new Error("Avatar upload failed");
      const avatarData = await avatarRes.json();

      // Update profile info
      const profileRes = await fetch(`${API_BASE}/users/me`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          hobbies,
          matchPref,
          locationRadius,
          ageRange,
          avatar: avatarData.filename,
          photos: photos.map((p) => p.name),
        }),
      });
      if (!profileRes.ok) throw new Error("Failed to save profile");
      const updatedUser = await profileRes.json();

      // ✅ Update App state
      setUser(updatedUser);

      // redirect to discover page
      navigate("/discover");
    } catch (err) {
      console.error(err);
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gradient-to-r from-purple-500 to-pink-500 px-4">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md sm:max-w-lg">
        {/* Step indicator */}
        <div className="text-center text-sm text-gray-500 mb-3">
          Step <span className="font-semibold text-purple-600">3 of 3</span> — Complete Your Profile
        </div>

        <h1 className="text-3xl font-bold text-center text-purple-600 mb-6">
          Complete Your Profile
        </h1>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Avatar upload */}
          <div>
            <label className="block mb-1 font-semibold">Profile Picture *</label>
            <input
              type="file"
              accept="image/*"
              onChange={handleAvatarChange}
              required
            />
            {avatarPreview && (
              <img
                src={avatarPreview}
                alt="Avatar Preview"
                className="mt-3 w-24 h-24 rounded-full object-cover border-2 border-purple-500 mx-auto"
              />
            )}
          </div>

          {/* Additional photos */}
          <div>
            <label className="block mb-1 font-semibold">
              Additional Photos / Reel (Optional)
            </label>
            <input
              type="file"
              accept="image/*,video/*"
              multiple
              onChange={handlePhotosChange}
            />
            {photoPreviews.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-3 justify-center">
                {photoPreviews.map((src, idx) => (
                  <img
                    key={idx}
                    src={src}
                    alt={`Preview ${idx + 1}`}
                    className="w-16 h-16 object-cover rounded-lg border"
                  />
                ))}
              </div>
            )}
          </div>

          {/* Hobbies */}
          <div>
            <label className="block mb-1 font-semibold">Hobbies</label>
            <input
              type="text"
              placeholder="Your hobbies"
              className="w-full p-3 border rounded-lg"
              value={hobbies}
              onChange={(e) => setHobbies(e.target.value)}
            />
          </div>

          {/* Match preferences */}
          <div>
            <label className="block mb-1 font-semibold">Looking For</label>
            <select
              className="w-full p-3 border rounded-lg"
              value={matchPref}
              onChange={(e) => setMatchPref(e.target.value)}
            >
              <option value="any">Any</option>
              <option value="male">Male</option>
              <option value="female">Female</option>
            </select>
          </div>

          {/* Age range */}
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="block mb-1 font-semibold">Age Min</label>
              <input
                type="number"
                className="w-full p-3 border rounded-lg"
                value={ageRange.min}
                min={18}
                max={ageRange.max}
                onChange={(e) =>
                  setAgeRange({ ...ageRange, min: Number(e.target.value) })
                }
              />
            </div>
            <div className="flex-1">
              <label className="block mb-1 font-semibold">Age Max</label>
              <input
                type="number"
                className="w-full p-3 border rounded-lg"
                value={ageRange.max}
                min={ageRange.min}
                max={100}
                onChange={(e) =>
                  setAgeRange({ ...ageRange, max: Number(e.target.value) })
                }
              />
            </div>
          </div>

          {/* Location radius */}
          <div>
            <label className="block mb-1 font-semibold">
              Location Radius (miles)
            </label>
            <input
              type="number"
              className="w-full p-3 border rounded-lg"
              value={locationRadius}
              min={1}
              max={100}
              onChange={(e) => setLocationRadius(Number(e.target.value))}
            />
          </div>

          {error && <p className="text-red-600 text-sm">{error}</p>}

          {/* Submit button */}
          <button
            type="submit"
            className="w-full py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition"
            disabled={loading}
          >
            {loading ? "Saving..." : "Finish & Start Discovering"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default CompleteProfile;
