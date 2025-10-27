import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaHeart, FaUserFriends, FaHandshake } from "react-icons/fa";
import { IoClose } from "react-icons/io5";
import { useNavigate } from "react-router-dom";

//const API_BASE = "http://localhost:4000/api";
const API_BASE = "http://localhost:4000/api";

// Add this helper function at the top (after imports)
const getToken = () =>
  localStorage.getItem("token") || sessionStorage.getItem("token") || "";

export default function SocialSection({ user }) {
  const token = getToken();
  const [stats, setStats] = useState({
    likedCount: 0,
    likedYouCount: 0,
    matchCount: 0,
  });
  const [list, setList] = useState([]);
  const [activeTab, setActiveTab] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Fetch counters
  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE}/users/social-stats`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then(setStats)
      .catch(console.error);
  }, [token]);

  // Open list - FIXED DATA HANDLING
  const openList = async (type) => {
    setActiveTab(type);
    setLoading(true);
    
    try {
      let response;
      
      if (type === "matches") {
        // Use matches endpoint
        response = await fetch(`${API_BASE}/matches`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await response.json();
        console.log("Matches data:", data); // Debug log
        
        // Handle different response structures
        if (data.matches && Array.isArray(data.matches)) {
          setList(data.matches);
        } else if (Array.isArray(data)) {
          setList(data);
        } else {
          setList([]);
        }
      } else {
        // Use social endpoint for liked/likedYou
        response = await fetch(`${API_BASE}/social/${type}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await response.json();
        console.log(`${type} data:`, data); // Debug log
        
        // Handle different response structures
        if (data.users && Array.isArray(data.users)) {
          setList(data.users);
        } else if (Array.isArray(data)) {
          setList(data);
        } else {
          setList([]);
        }
      }
    } catch (error) {
      console.error(`Error loading ${type}:`, error);
      setList([]);
    } finally {
      setLoading(false);
    }
  };

  const closeList = () => {
    setActiveTab(null);
    setList([]);
  };

  // Card hover animation
  const cardHover = {
    rest: { scale: 1, y: 0, boxShadow: "0 0 0 rgba(0,0,0,0)" },
    hover: {
      scale: 1.05,
      y: -4,
      boxShadow: "0 6px 20px rgba(0,0,0,0.15)",
      transition: { duration: 0.25 },
    },
  };

  return (
    <div className="mt-8 bg-gradient-to-br from-white/70 via-white/60 to-pink-50 rounded-2xl p-6 shadow-sm border border-rose-100">
      <h2 className="text-xl font-semibold text-gray-800 mb-5 flex items-center gap-2">
        <FaUserFriends className="text-rose-500" />
        Social Connections
      </h2>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-4">
        <motion.button
          variants={cardHover}
          initial="rest"
          whileHover="hover"
          onClick={() => openList("liked")}
          className="bg-white p-5 rounded-2xl text-center border border-gray-100 hover:border-rose-200 transition"
        >
          <FaHeart className="text-3xl text-rose-500 mx-auto mb-2" />
          <div className="text-2xl font-bold text-gray-800">{stats.likedCount}</div>
          <div className="text-sm text-gray-500">Liked</div>
        </motion.button>

        <motion.button
          variants={cardHover}
          initial="rest"
          whileHover="hover"
          onClick={() => openList("likedYou")}
          className="bg-white p-5 rounded-2xl text-center border border-gray-100 hover:border-pink-200 transition"
        >
          <FaHandshake className="text-3xl text-pink-500 mx-auto mb-2" />
          <div className="text-2xl font-bold text-gray-800">{stats.likedYouCount}</div>
          <div className="text-sm text-gray-500">Liked You</div>
        </motion.button>

        <motion.button
          variants={cardHover}
          initial="rest"
          whileHover="hover"
          onClick={() => openList("matches")}
          className="bg-white p-5 rounded-2xl text-center border border-gray-100 hover:border-rose-200 transition"
        >
          <FaUserFriends className="text-3xl text-rose-600 mx-auto mb-2" />
          <div className="text-2xl font-bold text-gray-800">{stats.matchCount}</div>
          <div className="text-sm text-gray-500">Matches</div>
        </motion.button>
      </div>

      {/* Modal */}
      <AnimatePresence>
        {activeTab && (
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.8, opacity: 0 }}
              className="bg-white rounded-2xl w-full max-w-md p-6 shadow-2xl relative"
            >
              <button
                onClick={closeList}
                className="absolute top-3 right-3 p-2 hover:bg-gray-100 rounded-full transition"
              >
                <IoClose className="text-2xl text-gray-600" />
              </button>

              <h3 className="text-xl font-semibold mb-4 capitalize text-gray-800 flex items-center gap-2">
                {activeTab === "liked" && <>❤️ People You Liked</>}
                {activeTab === "likedYou" && <>💘 People Who Liked You</>}
                {activeTab === "matches" && <>💞 Your Matches</>}
              </h3>

              {loading && (
                <div className="text-center py-8 text-gray-500 text-sm">
                  Loading profiles...
                </div>
              )}

              {!loading && (
                <>
                  <div className="text-sm text-gray-500 mb-3">
                    Showing {list.length} {list.length === 1 ? 'user' : 'users'}
                  </div>
                  
                  {list.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-10 text-gray-500">
                      <img
                        src="https://cdn-icons-png.flaticon.com/512/6596/6596115.png"
                        alt="empty"
                        className="h-20 w-20 opacity-70 mb-3"
                      />
                      <p>No users found here yet.</p>
                    </div>
                  ) : (
                    <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-2">
                      {list.map((u) => (
                        <div
                          key={u.id}
                          className="flex items-center gap-3 p-3 border border-gray-100 rounded-xl hover:bg-gray-50 transition"
                        >
                          <img
                            src={u.avatar || "https://via.placeholder.com/48?text=No+Photo"}
                            alt={u.firstName}
                            className="h-12 w-12 rounded-full object-cover border border-gray-200"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="font-semibold text-gray-800 truncate">
                              {u.firstName} {u.lastName}
                            </div>
                            <div className="text-sm text-gray-500 truncate">
                              {u.bio || "No bio yet"}
                            </div>
                          </div>
                          <button
                            onClick={() => navigate(`/view/${u.id}`)}
                            className="px-3 py-1.5 rounded-full bg-gradient-to-r from-rose-500 to-pink-500 text-white hover:scale-105 transition-transform"
                          >
                            View
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}