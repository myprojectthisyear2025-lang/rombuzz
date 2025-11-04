// src/pages/Register.jsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import logo from "../assets/logo.png";
import { useLocation } from "react-router-dom";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";

// Cloudinary (unsigned) — your confirmed values
const CLOUD_NAME = "drcxu0mks";
const UPLOAD_PRESET = "rombuzz_unsigned";

/* =========================
   Catalogs
========================= */
const GENDERS = ["Male", "Female", "Non-binary", "Other", "Prefer not to say"];

const LOOKING_FOR = [
  { key: "serious", label: "Long-term" },
  { key: "casual", label: "Casual" },
  { key: "friends", label: "Friends" },
  { key: "gymbuddy", label: "GymBuddy" },
];

const INTEREST_OPTIONS = [
  "Music", "Travel", "Movies", "Foodie", "Sports", "Art", "Books", "Gaming", "Fitness", "Pets",
  "Photography", "Dancing", "Coding", "Hiking", "Cooking", "Yoga", "Cycling", "Running", "Basketball",
  "Soccer", "Tennis", "Volleyball", "Swimming", "Camping", "Gardening", "Board Games", "Podcasting",
  "Stand-up Comedy", "Theatre", "Painting", "Writing", "Poetry", "Astrology", "Meditation", "Crafts",
  "Karaoke", "Live Music", "Coffee", "Tea", "Anime", "K-pop", "DIY", "Makeup", "Fashion", "Cars",
  "Tech", "Startups", "Investing", "Volunteering",
];

const VISIBILITY_MODES = [
  { key: "auto", label: "Auto (blur until match)" },
  { key: "limited", label: "Limited preview" },
  { key: "full", label: "Full profile" },
  { key: "hidden", label: "Hidden (not in Discover)" },
];

/* =========================
   Helpers
========================= */
const isValidDate = (value) => {
  if (!value) return false;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return false;
  // normalize back to yyyy-mm-dd and compare (catches 02/31 etc.)
  const iso = d.toISOString().slice(0, 10);
  return iso === value;
};

const isAdult = (isoDOB) => {
  if (!isoDOB || !isValidDate(isoDOB)) return false;
  const dob = new Date(isoDOB);
  const now = new Date();
  let age = now.getFullYear() - dob.getFullYear();
  const m = now.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < dob.getDate())) age--;
  return age >= 18;
};

const emailRegex = /\S+@\S+\.\S+/;

const uploadToCloudinary = async (file) => {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("upload_preset", UPLOAD_PRESET);
  const res = await fetch(`https://api.cloudinary.com/v1_1/${CLOUD_NAME}/upload`, {
    method: "POST",
    body: fd,
  });
  if (!res.ok) throw new Error("Cloudinary upload failed");
  return res.json();
};

const storeAuth = (token, user, remember = true) => {
  try {
    const s = remember ? localStorage : sessionStorage;
    s.setItem("token", token);
    s.setItem("user", JSON.stringify(user));
  } catch {}
};

/* =========================
   Component
========================= */
export default function Register({ setUser }) {
  const navigate = useNavigate();
const location = useLocation();
useEffect(() => {
  if (location.state?.verifiedEmail) {
    setEmail(location.state.verifiedEmail);
  }
}, [location.state]);

  // stage 0 = email verify, then steps 1..6 onboarding
  const [stage, setStage] = useState(0);

  // shared flags
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Stage 0 (email verify)
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [sent, setSent] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => {
    if (!sent) return;
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [sent, cooldown]);

  // Wizard steps 1..6
  const [step, setStep] = useState(1);
  const progressPct = useMemo(() => (step / 6) * 100, [step]);

  const [showPassword, setShowPassword] = useState(false);

  const [form, setForm] = useState({
    firstName: "",
    lastName: "",
    password: "",
    confirm: "",
    gender: "",
    dob: "", // yyyy-mm-dd
    lookingFor: "",
    interestedIn: [], // ["male","female","other"]
    ageMin: 18,
    ageMax: 35,
    distance: 25, // 0..1000
    visibilityMode: "auto",
    interests: [], // <=5
    phone: "",
    voiceUrl: "",
    photos: [],
    avatar: "",
  });

  const setField = (k, v) => setForm((p) => ({ ...p, [k]: v }));

  const toggleInterested = (key) =>
    setForm((p) => {
      const s = new Set(p.interestedIn);
      s.has(key) ? s.delete(key) : s.add(key);
      return { ...p, interestedIn: [...s] };
    });

  const toggleInterestChip = (value) =>
    setForm((p) => {
      const s = new Set(p.interests);
      if (s.has(value)) s.delete(value);
      else {
        if (s.size >= 5) return p; // max 5
        s.add(value);
      }
      return { ...p, interests: [...s] };
    });

  // set first photo as avatar if missing
  useEffect(() => {
    if (!form.avatar && form.photos.length > 0) {
      setField("avatar", form.photos[0]);
    }
  }, [form.photos]); // eslint-disable-line

/* -------------------------
   Stage 0 — Skip email verify (handled in Signup)
  --------------------------*/
useEffect(() => {
  const token = localStorage.getItem("token");
  const storedUser = localStorage.getItem("user");
  
  if (location.state?.verifiedEmail) {
    // Email verification flow
    setEmail(location.state.verifiedEmail);
    setStage(1);
    setTimeout(() => setStep(1), 100);
  } else if (token && storedUser) {
    // Google signup flow
    try {
      const userData = JSON.parse(storedUser);
      if (userData.email) {
        setEmail(userData.email);
        setStage(1);
        setTimeout(() => setStep(1), 100);
      } else {
        navigate("/signup");
      }
    } catch {
      navigate("/signup");
    }
  } else {
    navigate("/signup");
  }
}, [location.state, navigate]);


  /* -------------------------
   Step validations
  --------------------------*/
  const dobInvalid =
    form.dob && (!isValidDate(form.dob) || !isAdult(form.dob));

  const canNext1 =
    form.firstName.trim() &&
    form.lastName.trim() &&
    form.password.length >= 6 &&
    form.password === form.confirm &&
    form.gender &&
    form.dob &&
    isValidDate(form.dob) &&
    isAdult(form.dob) &&
    form.lookingFor &&
    form.interestedIn.length > 0;

  const canNext2 =
    form.ageMin >= 18 &&
    form.ageMin <= form.ageMax &&
    form.ageMax <= 100 &&
    form.distance >= 0 &&
    form.distance <= 1000;

  const canNext3 = form.interests.length > 0 && form.interests.length <= 5;
  const canNext4 = form.photos.length >= 2;

  /* -------------------------
   Photos
  --------------------------*/
  const onPickPhotos = async (files) => {
    if (!files || !files.length) return;
    setBusy(true);
    setError("");
    try {
      const urls = [];
      for (const f of files) {
        const up = await uploadToCloudinary(f);
        if (up.secure_url) urls.push(up.secure_url);
      }
      setForm((p) => ({ ...p, photos: [...p.photos, ...urls] }));
    } catch (e) {
      setError("Photo upload failed. Please try again.");
      console.error(e);
    } finally {
      setBusy(false);
    }
  };

  const removePhoto = (url) =>
    setForm((p) => {
      const arr = p.photos.filter((u) => u !== url);
      const next = { ...p, photos: arr };
      if (p.avatar === url) next.avatar = arr[0] || "";
      return next;
    });

  const setAsAvatar = (url) => setField("avatar", url);

  /* -------------------------
   Voice intro (optional)
  --------------------------*/
  const [recording, setRecording] = useState(false);
  const recRef = useRef(null);

  const startRecording = async () => {
    try {
      if (recording) return;
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const rec = new MediaRecorder(stream);
      const chunks = [];
      rec.ondataavailable = (e) => e.data.size > 0 && chunks.push(e.data);
      rec.onstop = async () => {
        setRecording(false);
        try {
          const blob = new Blob(chunks, { type: "audio/webm" });
          const file = new File([blob], "voiceIntro.webm", { type: "audio/webm" });
          const up = await uploadToCloudinary(file);
          if (up.secure_url) setField("voiceUrl", up.secure_url);
        } catch (e) {
          console.error(e);
          alert("Voice upload failed.");
        }
      };
      rec.start(100);
      recRef.current = rec;
      setRecording(true);
    } catch {
      alert("Microphone permission is required to record.");
    }
  };

  const stopRecording = () => {
    try {
      recRef.current?.stream?.getTracks?.().forEach((t) => t.stop());
      recRef.current?.stop?.();
      recRef.current = null;
    } catch {}
  };

  /* -------------------------
   Submit (finish)
  --------------------------*/
  const finish = async () => {
    setError("");
    if (!canNext4) {
      setError("Please complete all required sections.");
      return;
    }
    setBusy(true);
    try {
      const payload = {
        email: email.trim(),
        firstName: form.firstName.trim(),
        lastName: form.lastName.trim(),
        password: form.password,
        gender: form.gender,
        dob: form.dob,
        lookingFor: form.lookingFor,
        interestedIn: form.interestedIn,
        preferences: { ageRange: [form.ageMin, form.ageMax], distanceMiles: form.distance },
        visibilityMode: form.visibilityMode,
        interests: form.interests,
        avatar: form.avatar,
        photos: form.photos,
        phone: form.phone || "",
        voiceUrl: form.voiceUrl || "",
      };

      const res = await axios.post(`${API_BASE}/auth/register-full`, payload);
      const { token, user } = res.data || {};
      if (!token || !user) throw new Error("Malformed server response");

      storeAuth(token, user, true);
      setUser?.(user);
      navigate("/discover");
    } catch (e) {
      setError(
        e.response?.data?.error ||
          e.message ||
          "Registration failed. Please try again."
      );
    } finally {
      setBusy(false);
    }
  };

  /* -------------------------
   UI pieces
  --------------------------*/
  const Progress = () => (
    <div className="w-full h-2 bg-rose-100 rounded-full overflow-hidden mb-6">
      <div className="h-full bg-rose-500 transition-all" style={{ width: `${progressPct}%` }} />
    </div>
  );

  const cardVariants = {
    initial: { opacity: 0, y: 8 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -8 },
    transition: { duration: 0.18 },
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-gradient-to-r from-red-500 via-pink-500 to-rose-400">
      <div className="bg-white rounded-2xl shadow-xl p-6 md:p-8 w-full max-w-xl relative">
        {/* Header */}
        <div className="text-center mb-4">
          <img
            src={logo}
            alt="RomBuzz Logo"
            className="h-16 w-16 mx-auto animate-pulse-slow drop-shadow-lg"
          />
          <h1 className="text-2xl md:text-3xl font-bold text-red-600 mt-3">
            {stage === 0 ? "Verify your email" : "Create your RomBuzz"}
          </h1>
          <p className="text-gray-500 text-sm">
            {stage === 0 ? "We’ll start by verifying your email." : `Step ${step} of 6`}
          </p>
        </div>

        <AnimatePresence mode="wait">
        {stage === 0 ? (
  <motion.div key="stage0" {...cardVariants}>
    <div className="text-center py-12">
      <p className="text-gray-700 text-sm">
        Redirecting to signup… please wait.
      </p>
    </div>
  </motion.div>
) : (

            <motion.div key={`stage1-step${step}`} {...cardVariants}>
              {/* Wizard */}
              <Progress />
              {/* STEP 1 — Basic info */}
              {step === 1 && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <input
                      type="text"
                      placeholder="First name"
                      className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                      value={form.firstName}
                      onChange={(e) => setField("firstName", e.target.value)}
                    />
                    <input
                      type="text"
                      placeholder="Last name"
                      className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                      value={form.lastName}
                      onChange={(e) => setField("lastName", e.target.value)}
                    />
                  </div>

                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      placeholder="Password (min 6 chars)"
                      className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                      value={form.password}
                      onChange={(e) => setField("password", e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-3 text-sm text-gray-500"
                    >
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>

                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="Confirm password"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                    value={form.confirm}
                    onChange={(e) => setField("confirm", e.target.value)}
                  />

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <select
                      className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                      value={form.gender}
                      onChange={(e) => setField("gender", e.target.value)}
                    >
                      <option value="">Gender</option>
                      {GENDERS.map((g) => (
                        <option key={g} value={g}>
                          {g}
                        </option>
                      ))}
                    </select>

                    <input
                      type="date"
                      className={`w-full p-3 border rounded-lg focus:ring-2 ${
                        dobInvalid ? "border-rose-500 focus:ring-rose-300" : "focus:ring-pink-400"
                      }`}
                      value={form.dob}
                      onChange={(e) => setField("dob", e.target.value)}
                    />
                  </div>

                  {dobInvalid && (
                    <div className="text-xs text-rose-600">
                      Invalid date of birth. Please provide a valid date (18+).
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <select
                      className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                      value={form.lookingFor}
                      onChange={(e) => setField("lookingFor", e.target.value)}
                    >
                      <option value="">What are you looking for?</option>
                      {LOOKING_FOR.map((x) => (
                        <option key={x.key} value={x.key}>
                          {x.label}
                        </option>
                      ))}
                    </select>

                    <div className="w-full">
                      <div className="text-xs text-gray-500 mb-1">Interested in</div>
                      <div className="flex flex-wrap gap-2">
                        {["male", "female", "other"].map((k) => {
                          const active = form.interestedIn.includes(k);
                          return (
                            <button
                              key={k}
                              type="button"
                              onClick={() => toggleInterested(k)}
                              className={`px-3 py-2 rounded-full border text-sm ${
                                active
                                  ? "bg-rose-500 text-white border-rose-500"
                                  : "bg-white text-gray-700 border-gray-300 hover:border-rose-300"
                              }`}
                            >
                              {k[0].toUpperCase() + k.slice(1)}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>

                  <div className="flex justify-end pt-2">
                    <button
                      onClick={() => setStep(2)}
                      disabled={!canNext1}
                      className={`px-5 py-2 rounded-lg text-white ${
                        canNext1 ? "bg-red-600 hover:bg-red-700" : "bg-gray-300"
                      }`}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 2 — Preferences (clean UI) */}
              {step === 2 && (
                <div className="space-y-5">
                  <div className="rounded-xl border p-4">
                    <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                      <span>Preferred age range</span>
                      <span className="font-semibold">
                        {form.ageMin}–{form.ageMax}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <input
                          type="range"
                          min="18"
                          max="100"
                          value={form.ageMin}
                          onChange={(e) =>
                            setField("ageMin", Math.min(+e.target.value, form.ageMax))
                          }
                          className="w-full accent-rose-500"
                        />
                        <div className="text-xs text-gray-500 mt-1">Min: {form.ageMin}</div>
                      </div>
                      <div>
                        <input
                          type="range"
                          min="18"
                          max="100"
                          value={form.ageMax}
                          onChange={(e) =>
                            setField("ageMax", Math.max(+e.target.value, form.ageMin))
                          }
                          className="w-full accent-rose-500"
                        />
                        <div className="text-xs text-gray-500 mt-1">Max: {form.ageMax}</div>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-xl border p-4">
                    <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                      <span>Distance preference</span>
                      <span className="font-semibold">
                        {form.distance >= 1000 ? "1000+ miles" : `${form.distance} miles`}
                      </span>
                    </div>
                    <input
                      type="range"
                      min="0"
                      max="1000"
                      value={form.distance}
                      onChange={(e) => setField("distance", +e.target.value)}
                      className="w-full accent-rose-500"
                    />
                  </div>

                  <div>
                    <div className="text-sm text-gray-600 mb-2">Profile visibility</div>
                    <div className="flex flex-wrap gap-2">
                      {VISIBILITY_MODES.map((v) => {
                        const active = form.visibilityMode === v.key;
                        return (
                          <button
                            key={v.key}
                            onClick={() => setField("visibilityMode", v.key)}
                            type="button"
                            className={`px-3 py-2 rounded-full border text-sm ${
                              active
                                ? "bg-rose-500 text-white border-rose-500"
                                : "bg-white text-gray-700 border-gray-300 hover:border-rose-300"
                            }`}
                          >
                            {v.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  <div className="flex justify-between pt-2">
                    <button
                      onClick={() => setStep(1)}
                      className="px-4 py-2 rounded-lg border"
                    >
                      ← Back
                    </button>
                    <button
                      onClick={() => setStep(3)}
                      disabled={!canNext2}
                      className={`px-5 py-2 rounded-lg text-white ${
                        canNext2 ? "bg-red-600 hover:bg-red-700" : "bg-gray-300"
                      }`}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 3 — Interests */}
              {step === 3 && (
                <div className="space-y-4">
                  <div className="text-sm text-gray-600">
                    Pick up to <b>5</b> interests
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {INTEREST_OPTIONS.map((i) => {
                      const active = form.interests.includes(i);
                      return (
                        <button
                          key={i}
                          type="button"
                          onClick={() => toggleInterestChip(i)}
                          className={`px-3 py-2 rounded-lg border text-sm ${
                            active
                              ? "bg-pink-500 text-white border-pink-500"
                              : "bg-white text-gray-700 border-gray-300 hover:border-rose-300"
                          }`}
                        >
                          {i}
                        </button>
                      );
                    })}
                  </div>

                  <div className="flex justify-between pt-2">
                    <button onClick={() => setStep(2)} className="px-4 py-2 rounded-lg border">
                      ← Back
                    </button>
                    <button
                      onClick={() => setStep(4)}
                      disabled={!canNext3}
                      className={`px-5 py-2 rounded-lg text-white ${
                        canNext3 ? "bg-red-600 hover:bg-red-700" : "bg-gray-300"
                      }`}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 4 — Photos (min 2) */}
              {step === 4 && (
                <div className="space-y-4">
                  <div className="text-sm text-gray-600">
                    Upload at least <b>2 photos</b>. The first photo is your avatar (you can change it).
                  </div>

                  <div className="flex flex-col sm:flex-row gap-2 sm:items-center">
                    <label className="inline-flex items-center justify-center px-4 py-2 rounded-lg border cursor-pointer hover:bg-rose-50">
                      <input
                        type="file"
                        accept="image/*,video/*"
                        multiple
                        className="hidden"
                        onChange={(e) => onPickPhotos(Array.from(e.target.files || []))}
                      />
                      <span className="text-sm text-gray-700">Add photos</span>
                    </label>
                    <div className="text-xs text-gray-500">
                      PNG/JPG/MP4 allowed. Short videos will appear in your MyBuzz.
                    </div>
                  </div>

                  {form.photos.length > 0 ? (
                    <div className="grid grid-cols-3 sm:grid-cols-4 gap-3">
                      {form.photos.map((url) => {
                        const isAvatar = form.avatar === url;
                        return (
                          <div key={url} className="relative group">
                            <img
                              src={url}
                              alt=""
                              className={`w-full h-28 object-cover rounded-lg border ${
                                isAvatar ? "border-rose-500" : "border-gray-200"
                              }`}
                            />
                            <div className="absolute inset-x-0 bottom-1 flex justify-center gap-1 opacity-0 group-hover:opacity-100 transition">
                              {!isAvatar && (
                                <button
                                  type="button"
                                  onClick={() => setAsAvatar(url)}
                                  className="px-2 py-1 text-[11px] rounded bg-white/90 border"
                                >
                                  Set avatar
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={() => removePhoto(url)}
                                className="px-2 py-1 text-[11px] rounded bg-white/90 border"
                              >
                                Remove
                              </button>
                            </div>
                            {isAvatar && (
                              <div className="absolute top-1 left-1 text-[10px] bg-rose-600 text-white px-1.5 py-0.5 rounded">
                                Avatar
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-sm text-gray-500">No photos yet.</div>
                  )}

                  <div className="flex justify-between pt-2">
                    <button onClick={() => setStep(3)} className="px-4 py-2 rounded-lg border">
                      ← Back
                    </button>
                    <button
                      onClick={() => setStep(5)}
                      disabled={!canNext4}
                      className={`px-5 py-2 rounded-lg text-white ${
                        canNext4 ? "bg-red-600 hover:bg-red-700" : "bg-gray-300"
                      }`}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 5 — Optional (phone + voice) */}
              {step === 5 && (
                <div className="space-y-4">
                  <input
                    type="tel"
                    placeholder="Phone number (optional)"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-pink-400"
                    value={form.phone}
                    onChange={(e) => setField("phone", e.target.value)}
                  />

                  <div>
                    <div className="text-sm text-gray-600 mb-1">Voice intro (optional)</div>
                    <div className="flex flex-wrap items-center gap-2">
                      {!recording ? (
                        <button
                          type="button"
                          onClick={startRecording}
                          className="px-3 py-2 rounded-lg border hover:bg-rose-50"
                        >
                          Record
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={stopRecording}
                          className="px-3 py-2 rounded-lg border hover:bg-rose-50"
                        >
                          Stop & upload
                        </button>
                      )}
                      {form.voiceUrl && <audio src={form.voiceUrl} controls className="w-full mt-2" />}
                    </div>
                    <div className="text-[11px] text-gray-400 mt-1">
                      A short hello (≤60s) helps break the ice.
                    </div>
                  </div>

                  <div className="flex justify-between pt-2">
                    <button onClick={() => setStep(4)} className="px-4 py-2 rounded-lg border">
                      ← Back
                    </button>
                    <button
                      onClick={() => setStep(6)}
                      className="px-5 py-2 rounded-lg text-white bg-red-600 hover:bg-red-700"
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 6 — Summary & Finish */}
              {step === 6 && (
                <div className="space-y-4">
                  <div className="bg-rose-50 rounded-lg p-3 text-sm">
                    <div>
                      <b>Name:</b> {form.firstName} {form.lastName}
                    </div>
                    <div>
                      <b>Email:</b> {email}
                    </div>
                    <div>
                      <b>Gender:</b> {form.gender} &nbsp; | &nbsp;
                      <b>DOB:</b> {form.dob}
                    </div>
                    <div>
                      <b>Looking for:</b>{" "}
                      {LOOKING_FOR.find((x) => x.key === form.lookingFor)?.label || ""}
                    </div>
                    <div>
                      <b>Interested in:</b> {form.interestedIn.join(", ")}
                    </div>
                    <div>
                      <b>Age range:</b> {form.ageMin}–{form.ageMax} &nbsp; | &nbsp;
                      <b>Distance:</b> {form.distance >= 1000 ? "1000+ miles" : `${form.distance} miles`}
                    </div>
                    <div>
                      <b>Visibility:</b>{" "}
                      {VISIBILITY_MODES.find((v) => v.key === form.visibilityMode)?.label}
                    </div>
                    <div>
                      <b>Interests:</b> {form.interests.join(", ")}
                    </div>
                    <div className="mt-2">
                      <b>Photos:</b> {form.photos.length} (avatar marked)
                    </div>
                  </div>

                  {error && <div className="text-rose-600 text-sm">{error}</div>}

                  <div className="flex justify-between pt-2">
                    <button onClick={() => setStep(5)} className="px-4 py-2 rounded-lg border">
                      ← Back
                    </button>
                    <button
                      onClick={finish}
                      disabled={!canNext4 || busy}
                      className={`px-5 py-2 rounded-lg text-white ${
                        !canNext4 || busy ? "bg-gray-300" : "bg-red-600 hover:bg-red-700"
                      }`}
                    >
                      {busy ? "Creating..." : "Finish & Create My RomBuzz →"}
                    </button>
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

/* Slow pulse animation for logo */
const style = document.createElement("style");
style.innerHTML = `
@keyframes pulse-slow {
  0%, 100% { transform: scale(1); filter: drop-shadow(0 0 0px rgba(255,255,255,0.5)); }
  50% { transform: scale(1.08); filter: drop-shadow(0 0 8px rgba(255,255,255,0.8)); }
}
.animate-pulse-slow { animation: pulse-slow 2.5s infinite ease-in-out; }
`;
document.head.appendChild(style);
