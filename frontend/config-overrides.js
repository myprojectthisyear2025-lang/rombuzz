const webpack = require("webpack");
const path = require("path");

module.exports = function override(config) {
  config.resolve.fallback = {
    ...config.resolve.fallback,
    process: require.resolve("process/browser.js"),
    stream: require.resolve("stream-browserify"),
    util: require.resolve("util"),
  };

  config.resolve.alias = {
    ...(config.resolve.alias || {}),
    "process/browser.js": path.resolve(__dirname, "node_modules/process/browser.js"),
  };

  config.plugins = [
    ...(config.plugins || []),
    new webpack.ProvidePlugin({
      process: "process/browser.js",
    }),
  ];

  return config;
};
