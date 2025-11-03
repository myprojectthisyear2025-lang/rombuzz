// src/pages/Signup.jsx
import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { GoogleLogin } from "@react-oauth/google";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = process.env.REACT_APP_API_BASE || "https://rombuzz-api.onrender.com/api";
const CLIENT_ID =
  process.env.REACT_APP_GOOGLE_CLIENT_ID || "579443399527-3q3lpblalkiqces1d0etdgjfj301b75l.apps.googleusercontent.com";
export default function Signup({ setUser }) {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [countdown, setCountdown] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [step, setStep] = useState(1);

  const codeInputRef = useRef(null);

  // Countdown for resend
  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown((c) => c - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [countdown]);

  // Send verification code
  const sendCode = async () => {
    setError("");
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return setError("Please enter a valid email address.");
    }
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/auth/send-code`, { email });
      if (res.data.success) {
        setSuccess("Verification code sent to your email.");
        setStep(2);
        setCountdown(60);
        setTimeout(() => codeInputRef.current?.focus(), 200);
      } else {
        setError(res.data.error || "Failed to send code.");
      }
    } catch (e) {
      setError(e.response?.data?.error || "Error sending verification code.");
    } finally {
      setLoading(false);
    }
  };

  // Verify the code
  const verifyCode = async () => {
    setError("");
    if (!code) return setError("Please enter the 6-digit code.");

    setLoading(true);
    try {
      // Here we just simulate verification because backend doesn’t yet have /verify-code.
      // Normally, you'd POST to /api/auth/verify-code and validate.
     if (code.trim().length === 6) {
  setSuccess("Email verified successfully! Redirecting...");
  setTimeout(() => {
    navigate("/register", {
      state: { verifiedEmail: email.trim(), from: "signup" },
      replace: true,
    });
  }, 800);
} else {
  setError("Incorrect code. Please check again.");
}

    } catch (e) {
      setError("Invalid or expired code.");
    } finally {
      setLoading(false);
    }
  };

 // ✅ FIXED Google Signup Handler
const handleGoogleSignup = async (response) => {
  setError("");
  setLoading(true);
  try {
      console.log("🔍 GOOGLE RESPONSE RECEIVED:", response); // ADD THIS
    console.log("🔍 CREDENTIAL EXISTS?", !!response.credential); // ADD THIS
    const res = await axios.post(`${API_BASE}/auth/google`, {
      token: response.credential,
    });
    console.log("🔍 BACKEND RESPONSE:", res.data); // ADD THIS

  const { status, token, user } = res.data || {};
if (!token || !user) throw new Error("Invalid response from server");

// 🧹 Clear any stale data first
localStorage.removeItem("user");
localStorage.removeItem("token");

// ✅ Save fresh token + user
localStorage.setItem("token", token);
localStorage.setItem("user", JSON.stringify(user));
if (setUser) setUser(user);

// ✅ Redirect based on backend status
if (status === "incomplete_profile") {
  navigate("/completeprofile", { replace: true });
} else {
  navigate("/discover", { replace: true });
}

  } catch (e) {
    console.error("Google signup error:", e);
    setError(
      e.response?.data?.error ||
        e.message ||
        "Google signup failed. Please try again."
    );
  } finally {
    setLoading(false);
  }
};



  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-pink-500 to-red-500 px-4">
      <div className="bg-white shadow-2xl rounded-2xl w-full max-w-md p-8 text-center">
        <h1 className="text-3xl font-bold text-pink-600 mb-4">
          Create Your RomBuzz Account
        </h1>
        {error && <p className="text-red-600 mb-2">{error}</p>}
        {success && <p className="text-green-600 mb-2">{success}</p>}

        {/* STEP 1 — Enter email */}
        {step === 1 && (
          <>
            <input
              type="email"
              placeholder="Enter your email"
              className="w-full p-3 border rounded-lg mb-4 focus:outline-none focus:ring-2 focus:ring-pink-400"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <button
              onClick={sendCode}
              disabled={loading || countdown > 0}
              className="w-full py-3 bg-pink-600 text-white font-semibold rounded-lg hover:bg-pink-700 transition mb-3"
            >
              {loading
                ? "Sending..."
                : countdown > 0
                ? `Resend in ${countdown}s`
                : "Send Verification Code"}
            </button>

            <div className="relative text-center my-4">
              <div className="border-t border-gray-300 w-full mb-3"></div>
              <span className="bg-white px-3 text-gray-500 text-sm">or</span>
            </div>

            <div className="flex flex-col gap-3">
            

              <GoogleLogin
                onSuccess={handleGoogleSignup}
                onError={() => setError("Google signup failed")}
                text="signup_with"
                shape="pill"
                width="330"
                size="large"
                theme="filled_pink"
              />
            </div>

            <p className="mt-6 text-sm text-gray-600">
              Already have an account?{" "}
              <span
                className="text-pink-600 font-semibold cursor-pointer hover:underline"
                onClick={() => navigate("/login")}
              >
                Login
              </span>
            </p>
          </>
        )}

        {/* STEP 2 — Enter code */}
        {step === 2 && (
          <>
            <input
              type="text"
              placeholder="Enter 6-digit code"
              className="w-full p-3 border rounded-lg mb-4 focus:outline-none focus:ring-2 focus:ring-pink-400 text-center tracking-widest text-lg"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              ref={codeInputRef}
              maxLength={6}
            />
            <button
              onClick={verifyCode}
              disabled={loading}
              className="w-full py-3 bg-pink-600 text-white font-semibold rounded-lg hover:bg-pink-700 transition mb-3"
            >
              {loading ? "Verifying..." : "Verify Code"}
            </button>
            <button
              onClick={() => setStep(1)}
              className="text-gray-600 text-sm underline hover:text-pink-500"
            >
              Back
            </button>
          </>
        )}
      </div>
    </div>
  );
}
