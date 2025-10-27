import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FaUsers,
  FaComments,
  FaShieldAlt,
  FaCompass,
  FaBolt,
  FaHeart,
  FaMapMarkerAlt,
} from "react-icons/fa";

// Import your logo
import logo from "../assets/logo.png";

export default function Home() {
  const navigate = useNavigate();
  const [showAnimation, setShowAnimation] = useState(true);
  const user =
    JSON.parse(localStorage.getItem("user")) ||
    JSON.parse(sessionStorage.getItem("user"));

  useEffect(() => {
    const timer = setTimeout(() => {
      setShowAnimation(false);
    }, 1500); // Reduced to 2 seconds

    return () => clearTimeout(timer);
  }, []);
  // 🌗 Load saved Buzz Night preference
useEffect(() => {
  const savedMode = localStorage.getItem("buzzNightMode");
  if (savedMode === "true") document.body.classList.add("buzz-night");
}, []);


  if (showAnimation) {
    return <LogoAnimation />;
  }
{/* Floating Neon Toggle */}
<button
  onClick={() => document.body.classList.toggle('buzz-night')}
  className="buzz-toggle-b fixed top-6 right-6 px-5 py-2 rounded-full z-50 shadow-xl hover:scale-105 transition-transform duration-300"
>
  🌗 Buzz Mode
</button>

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 to-pink-50 overflow-x-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-red-100/40 via-pink-100/20 to-white"></div>
        <div className="absolute top-1/4 left-1/4 w-72 h-72 bg-red-300/30 rounded-full blur-3xl animate-float-slow"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-pink-300/30 rounded-full blur-3xl animate-float-slower"></div>
        
        {/* Animated dots */}
        <div className="absolute top-1/3 left-1/4 w-4 h-4 bg-red-400/50 rounded-full animate-pulse"></div>
        <div className="absolute top-2/3 right-1/3 w-3 h-3 bg-pink-400/50 rounded-full animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute bottom-1/4 left-1/3 w-2 h-2 bg-red-300/60 rounded-full animate-pulse" style={{animationDelay: '2s'}}></div>
      </div>

      {/* Main Content */}
      <div className="relative z-10">
        {/* Hero Section */}
        <div className="bg-gradient-to-r from-red-500 to-pink-600 text-white w-full py-20 md:py-28 text-center relative overflow-hidden">
          {/* Background decorative elements */}
          <div className="absolute inset-0 overflow-hidden">
            <div className="absolute -top-20 -right-20 w-48 h-48 bg-white/10 rounded-full blur-2xl"></div>
            <div className="absolute -bottom-28 -left-28 w-64 h-64 bg-pink-400/20 rounded-full blur-2xl"></div>
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-80 h-80 bg-red-400/15 rounded-full blur-3xl"></div>
          </div>

          <div className="relative z-10 container mx-auto px-4">
        {/* Logo instead of jumping heart */}
<div className="flex justify-center mb-8 relative">
  {/* 🌗 Buzz Mode Toggle (Option A — top-right corner, glassy) */}
  <div className="absolute -top-10 right-0 md:-top-12 md:-right-12 z-50">
    <button
      onClick={() => document.body.classList.toggle('buzz-night')}
      className="bg-white/10 hover:bg-white/20 text-white text-sm font-semibold px-4 py-2 rounded-full backdrop-blur-lg border border-white/30 shadow-lg transition-all duration-500"
    >
      🌙 Buzz Mode
    </button>
  </div>

  <div className="bg-white/20 backdrop-blur-lg rounded-2xl p-4 shadow-2xl border border-white/30 animate-bounce-gentle">
    <img
      src={logo}
      alt="Rombuzz"
      className="w-16 h-16 object-contain"
    />
  </div>
</div>

            {/* Animated Header */}
            <div className="mb-8">
              <div className="inline-block">
                <h1 className="text-5xl md:text-7xl lg:text-8xl font-black mb-6 animate-glow montserrat-font">
                  {user ? (
                    <>
                      Hey <span className="text-yellow-200">{user.firstName || "there"}</span>! 
                    </>
                  ) : (
                    <span className="text-transparent bg-clip-text bg-gradient-to-r from-white to-yellow-100 animate-gradient montserrat-font">
                      Rombuzz
                    </span>
                  )}
                </h1>
              </div>
            </div>

            <p className="text-xl md:text-2xl mb-12 font-light opacity-95 max-w-3xl mx-auto leading-relaxed">
              {user 
                ? "Ready to make real connections?" 
                : "Connect with people nearby in real-time"}
            </p>

            {!user ? (
              // 👥 Guest view
              <div className="flex flex-col sm:flex-row gap-6 justify-center items-center animate-fade-up">
                <button
                  onClick={() => navigate("/signup")}
                  className="group relative bg-white text-red-600 font-bold px-12 py-5 rounded-2xl hover:bg-gray-50 transition-all duration-500 transform hover:scale-105 hover:-translate-y-1 shadow-2xl overflow-hidden montserrat-font border-2 border-transparent hover:border-red-200"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-500/5 to-transparent -skew-x-12 animate-shine"></div>
                  <span className="relative flex items-center gap-3 text-lg">
                    Get Started
                    <span className="group-hover:translate-x-1 transition-transform">→</span>
                  </span>
                </button>
                <button
                  onClick={() => navigate("/login")}
                  className="group border-2 border-white/80 text-white font-bold px-12 py-5 rounded-2xl hover:bg-white/15 transition-all duration-500 transform hover:scale-105 backdrop-blur-sm hover:border-white flex items-center gap-3 text-lg montserrat-font hover:shadow-xl"
                >
                  Login
                  <span className="group-hover:translate-x-1 transition-transform">→</span>
                </button>
              </div>
            ) : (
              // 💕 Logged-in view - Enhanced Cards
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-4xl mx-auto mt-16">
                {/* Discover Card */}
                <div
                  onClick={() => navigate("/discover")}
                  className="group cursor-pointer bg-white/15 hover:bg-white/25 backdrop-blur-lg p-8 rounded-3xl border border-white/25 hover:border-white/45 transition-all duration-500 transform hover:-translate-y-3 hover:scale-105 shadow-2xl relative overflow-hidden"
                >
                  {/* Removed blue gradient line */}
                  <div className="absolute inset-0 bg-gradient-to-br from-transparent via-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  <div className="relative z-10">
                    <div className="bg-white/25 rounded-2xl p-5 mb-6 group-hover:scale-110 group-hover:rotate-6 transition-transform duration-500 shadow-lg">
                      <FaCompass className="text-3xl text-white" />
                    </div>
                    <h2 className="text-3xl font-bold mb-4 text-white montserrat-font">Discover</h2>
                    <p className="text-white/85 text-center leading-relaxed font-medium">
                      Explore matches anywhere - near or far. Find your perfect buzz.
                    </p>
                    <div className="mt-6 flex items-center justify-center gap-2 text-white/70 group-hover:text-white transition-colors">
                      <FaMapMarkerAlt className="text-sm" />
                      <span className="text-sm font-medium">Location-based matching</span>
                    </div>
                  </div>
                </div>
             


                {/* MicroBuzz Card */}
                <div
                  onClick={() => navigate("/microbuzz")}
                  className="group cursor-pointer bg-white/15 hover:bg-white/25 backdrop-blur-lg p-8 rounded-3xl border border-white/25 hover:border-white/45 transition-all duration-500 transform hover:-translate-y-3 hover:scale-105 shadow-2xl relative overflow-hidden"
                >
                  {/* Removed yellow gradient line */}
                  <div className="absolute inset-0 bg-gradient-to-br from-transparent via-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                  <div className="relative z-10">
                    <div className="bg-white/25 rounded-2xl p-5 mb-6 group-hover:scale-110 group-hover:-rotate-6 transition-transform duration-500 shadow-lg">
                      <FaBolt className="text-3xl text-white animate-pulse-slow" />
                    </div>
                    <h2 className="text-3xl font-bold mb-4 text-white montserrat-font">MicroBuzz</h2>
                    <p className="text-white/85 text-center leading-relaxed font-medium">
                      Go live now - match in real time with nearby users. Instant connections.
                    </p>
                    <div className="mt-6 flex items-center justify-center gap-2 text-white/70 group-hover:text-white transition-colors">
                      <FaBolt className="text-sm" />
                      <span className="text-sm font-medium">Real-time matching</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Feature Section */}
        <div className="py-20 px-4 relative">
          <div className="absolute inset-0 bg-gradient-to-b from-transparent to-red-50/50"></div>
          <div className="relative z-10 container mx-auto max-w-6xl">
            <div className="text-center mb-16">
              <h2 className="text-4xl md:text-5xl font-black text-gray-900 mb-6 montserrat-font">
                Why Choose <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-pink-600">Rombuzz</span>?
              </h2>
              <p className="text-xl text-gray-600 max-w-2xl mx-auto font-medium">
                Experience dating that feels natural, spontaneous, and authentic where Romance meets Buzz.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="group bg-white rounded-3xl p-8 text-center shadow-xl hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-3 border border-gray-100 hover:border-red-100">
                <div className="bg-gradient-to-br from-red-500 to-pink-600 w-20 h-20 rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:scale-110 group-hover:rotate-12 transition-transform duration-500 shadow-lg">
                  <FaUsers className="text-2xl text-white" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-4 montserrat-font">Meet Real People</h3>
                <p className="text-gray-600 leading-relaxed font-medium">
                  Discover authentic connections with people who share your interests and are ready to meet now.
                </p>
              </div>

              <div className="group bg-white rounded-3xl p-8 text-center shadow-xl hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-3 border border-gray-100 hover:border-pink-100">
                <div className="bg-gradient-to-br from-red-500 to-pink-600 w-20 h-20 rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:scale-110 group-hover:-rotate-12 transition-transform duration-500 shadow-lg">
                  <FaComments className="text-2xl text-white" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-4 montserrat-font">Instant Connection</h3>
                <p className="text-gray-600 leading-relaxed font-medium">
                  Start meaningful conversations instantly with real-time matching and live chat features.
                </p>
              </div>

              <div className="group bg-white rounded-3xl p-8 text-center shadow-xl hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-3 border border-gray-100 hover:border-red-100">
                <div className="bg-gradient-to-br from-red-500 to-pink-600 w-20 h-20 rounded-2xl flex items-center justify-center mx-auto mb-6 group-hover:scale-110 group-hover:rotate-12 transition-transform duration-500 shadow-lg">
                  <FaShieldAlt className="text-2xl text-white" />
                </div>
                <h3 className="text-2xl font-bold text-gray-900 mb-4 montserrat-font">Safe & Secure</h3>
                <p className="text-gray-600 leading-relaxed font-medium">
                  Your privacy and safety are our top priority with verified profiles and secure communication.
                </p>
              </div>
            </div>
          </div>
        </div>

              {/* Live Status Footer */}
        <div className="border-t border-gray-200 py-8 bg-white/80 backdrop-blur-sm">
          <div className="container mx-auto px-4 text-center">
            <div className="flex flex-col sm:flex-row justify-center items-center gap-4 text-gray-600">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse shadow-lg"></div>
                <span className="text-sm font-medium">Live connections active</span>
              </div>
              <div className="text-sm font-medium">
              </div>
            </div>
          </div>
        </div>

      {/* 🌗 Bottom-right floating icon toggle */}
<button
  onClick={() => {
    document.body.classList.toggle("buzz-night");
    const active = document.body.classList.contains("buzz-night");
    localStorage.setItem("buzzNightMode", active ? "true" : "false");
  }}
  className="buzz-toggle-c"
  title="Toggle Buzz Mode"
>
  🌗
</button>


      </div>
    </div>
  );
}


// Logo Animation Component
function LogoAnimation() {
  return (
    <div className="fixed inset-0 bg-gradient-to-br from-red-500 to-pink-600 flex items-center justify-center z-50">
      <div className="relative">
        {/* Main Logo Container */}
        <div className="relative">
          {/* Outer Orbital Rings */}
          <div className="absolute -inset-8 border-4 border-white/30 rounded-full animate-spin-slow"></div>
          <div className="absolute -inset-12 border-2 border-white/20 rounded-full animate-spin-slower"></div>
          
          {/* Pulsing Core with Logo */}
          <div className="w-32 h-32 bg-white/20 backdrop-blur-lg rounded-2xl flex items-center justify-center shadow-2xl animate-pulse-rapid border border-white/30">
            <img 
              src={logo} 
              alt="Rombuzz" 
              className="w-20 h-20 object-contain animate-scale-in"
            />
          </div>
        </div>
        
        {/* Floating Particles */}
        <div className="absolute inset-0">
          {[1, 2, 3, 4, 5, 6].map((particle) => (
            <div
              key={particle}
              className={`absolute w-2 h-2 bg-white/60 rounded-full animate-float-particle-${particle}`}
            ></div>
          ))}
        </div>

        {/* Text Reveal */}
        <div className="absolute -bottom-24 left-1/2 transform -translate-x-1/2">
          <h1 className="text-6xl font-black text-white animate-text-reveal montserrat-font tracking-wide">
            Rombuzz
          </h1>
        </div>
      </div>
    </div>
  );
}

/* ✨ Enhanced Animations with Montserrat Font */
const style = document.createElement("style");
style.innerHTML = `
/* Import Montserrat Font */
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800;900&display=swap');

.montserrat-font {
  font-family: 'Montserrat', sans-serif;
}

/* Logo Animation Styles */
@keyframes spin-slow {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

@keyframes spin-slower {
  from { transform: rotate(0deg); }
  to { transform: rotate(-360deg); }
}

@keyframes pulse-rapid {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.05); opacity: 0.9; }
}

@keyframes scale-in {
  0% { transform: scale(0); opacity: 0; }
  70% { transform: scale(1.1); opacity: 0.8; }
  100% { transform: scale(1); opacity: 1; }
}

@keyframes text-reveal {
  0% { 
    opacity: 0; 
    transform: translateY(30px);
    filter: blur(10px);
  }
  100% { 
    opacity: 1; 
    transform: translateY(0);
    filter: blur(0);
  }
}

@keyframes float-particle-1 {
  0%, 100% { transform: translate(0px, 0px); opacity: 0.7; }
  50% { transform: translate(20px, -30px); opacity: 1; }
}

@keyframes float-particle-2 {
  0%, 100% { transform: translate(0px, 0px); opacity: 0.7; }
  50% { transform: translate(-25px, 25px); opacity: 1; }
}

@keyframes float-particle-3 {
  0%, 100% { transform: translate(0px, 0px); opacity: 0.7; }
  50% { transform: translate(30px, 15px); opacity: 1; }
}

@keyframes float-particle-4 {
  0%, 100% { transform: translate(0px, 0px); opacity: 0.7; }
  50% { transform: translate(-15px, -25px); opacity: 1; }
}

@keyframes float-particle-5 {
  0%, 100% { transform: translate(0px, 0px); opacity: 0.7; }
  50% { transform: translate(25px, -20px); opacity: 1; }
}

@keyframes float-particle-6 {
  0%, 100% { transform: translate(0px, 0px); opacity: 0.7; }
  50% { transform: translate(-30px, 10px); opacity: 1; }
}

.animate-spin-slow {
  animation: spin-slow 3s linear infinite;
}

.animate-spin-slower {
  animation: spin-slower 4s linear infinite;
}

.animate-pulse-rapid {
  animation: pulse-rapid 1s ease-in-out infinite;
}

.animate-scale-in {
  animation: scale-in 0.8s ease-out forwards;
}

.animate-text-reveal {
  animation: text-reveal 1.2s ease-out forwards;
  animation-delay: 0.5s;
  opacity: 0;
}

/* Main Page Animations */
@keyframes float-slow {
  0%, 100% { transform: translateY(0px) rotate(0deg); }
  50% { transform: translateY(-15px) rotate(180deg); }
}

@keyframes float-slower {
  0%, 100% { transform: translateY(0px) rotate(0deg); }
  50% { transform: translateY(20px) rotate(-180deg); }
}

@keyframes shine {
  0% { transform: translateX(-100%) skewX(-12deg); }
  100% { transform: translateX(200%) skewX(-12deg); }
}

@keyframes bounce-gentle {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-8px); }
}

@keyframes glow {
  0%, 100% { 
    text-shadow: 0 0 20px rgba(255, 255, 255, 0.5);
  }
  50% { 
    text-shadow: 0 0 40px rgba(255, 255, 255, 0.8), 0 0 60px rgba(255, 255, 255, 0.6);
  }
}

@keyframes gradient {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

@keyframes pulse-slow {
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.1); opacity: 0.8; }
}

/* Apply Animations */
.animate-float-slow { animation: float-slow 8s ease-in-out infinite; }
.animate-float-slower { animation: float-slower 10s ease-in-out infinite; }
.animate-shine { animation: shine 3s ease-in-out infinite; }
.animate-bounce-gentle { animation: bounce-gentle 3s ease-in-out infinite; }
.animate-glow { animation: glow 4s ease-in-out infinite; }
.animate-pulse-slow { animation: pulse-slow 2s ease-in-out infinite; }
.animate-gradient { 
  background-size: 200% 200%;
  animation: gradient 4s ease infinite; 
}

/* Particle animations */
.animate-float-particle-1 { animation: float-particle-1 4s ease-in-out infinite; }
.animate-float-particle-2 { animation: float-particle-2 5s ease-in-out infinite; }
.animate-float-particle-3 { animation: float-particle-3 6s ease-in-out infinite; }
.animate-float-particle-4 { animation: float-particle-4 7s ease-in-out infinite; }
.animate-float-particle-5 { animation: float-particle-5 8s ease-in-out infinite; }
.animate-float-particle-6 { animation: float-particle-6 9s ease-in-out infinite; }

/* Smooth fade animations */
@keyframes fade-up {
  from { opacity: 0; transform: translateY(30px); }
  to { opacity: 1; transform: translateY(0); }
}

.animate-fade-up {
  animation: fade-up 1s ease-out forwards;
}

/* Enhanced hover effects */
.group:hover .group-hover\\:rotate-6 {
  transform: rotate(6deg);
}

.group:hover .group-hover\\:-rotate-6 {
  transform: rotate(-6deg);
}
 /* === 🌗 Buzz Mode Night Theme === */
body.buzz-night {
  background: radial-gradient(circle at 20% 20%, #120018, #000) !important;
  color: #fff;
}
body.buzz-night .montserrat-font {
  background: linear-gradient(90deg, #ff7ad9, #7ad6ff);
  -webkit-background-clip: text;
  color: transparent;
  text-shadow: 0 0 20px rgba(255, 100, 200, 0.4);
}

/* === Toggle Button Variants === */

/* Option A (default): subtle glass look */
.buzz-toggle-a {
  background: rgba(255, 255, 255, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.25);
  color: white;
  backdrop-filter: blur(10px);
}

/* Option B: neon glowing pill button */
.buzz-toggle-b {
  background: linear-gradient(90deg, #ff4f8b, #ffcc70);
  color: #fff;
  box-shadow: 0 0 12px rgba(255, 120, 210, 0.5);
  font-weight: 700;
  letter-spacing: 0.5px;
}

/* Option C: compact icon-only button (bottom-right corner) */
.buzz-toggle-c {
  position: fixed;
  bottom: 1.5rem;
  right: 1.5rem;
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.25);
  border-radius: 50%;
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  backdrop-filter: blur(10px);
  z-index: 999;
  transition: all 0.3s ease;
}
.buzz-toggle-c:hover {
  transform: scale(1.1);
  background: rgba(255, 255, 255, 0.25);
}


`;
document.head.appendChild(style);