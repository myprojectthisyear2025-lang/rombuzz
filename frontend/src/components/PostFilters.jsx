import React from "react";
import { FaTimes, FaSearch } from "react-icons/fa";

export default function PostFilters({ filters, onChange, onClose }) {
  const updateFilter = (key, value) => {
    onChange({ ...filters, [key]: value });
  };

  return (
    <div className="bg-white rounded-2xl shadow-lg p-4 mb-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="font-semibold text-gray-800">Filter Posts</h3>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
          <FaTimes />
        </button>
      </div>

      <div className="space-y-4">
        {/* Search */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Search
          </label>
          <div className="relative">
            <FaSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={filters.search}
              onChange={(e) => updateFilter("search", e.target.value)}
              placeholder="Search posts..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-1 focus:ring-pink-500 focus:border-pink-500"
            />
          </div>
        </div>

        {/* Post Type */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Post Type
          </label>
          <select
            value={filters.type}
            onChange={(e) => updateFilter("type", e.target.value)}
            className="w-full border border-gray-300 rounded-lg p-2 focus:ring-1 focus:ring-pink-500 focus:border-pink-500"
          >
            <option value="all">All Types</option>
            <option value="text">Text Only</option>
            <option value="photo">Photos</option>
            <option value="reel">Reels</option>
            <option value="story">Stories</option>
          </select>
        </div>

        {/* Sort */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Sort By
          </label>
          <select
            value={filters.sort}
            onChange={(e) => updateFilter("sort", e.target.value)}
            className="w-full border border-gray-300 rounded-lg p-2 focus:ring-1 focus:ring-pink-500 focus:border-pink-500"
          >
            <option value="newest">Newest First</option>
            <option value="popular">Most Popular</option>
          </select>
        </div>

        {/* Clear Filters */}
        <button
          onClick={() => onChange({
            type: "all",
            search: "",
            sort: "newest"
          })}
          className="w-full py-2 border border-gray-300 text-gray-600 rounded-lg hover:bg-gray-50 transition"
        >
          Clear All Filters
        </button>
      </div>
    </div>
  );
}