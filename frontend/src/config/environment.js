// Environment configuration
const config = {
  development: {
    API_BASE_URL: process.env.REACT_APP_API_URL || "http://localhost:5000/api",
    WS_URL: process.env.REACT_APP_WS_URL || "ws://localhost:5000/ws",
    DEBUG_MODE: process.env.REACT_APP_DEBUG_MODE === "true",
    LOG_LEVEL: process.env.REACT_APP_LOG_LEVEL || "debug",
  },
  production: {
    API_BASE_URL: process.env.REACT_APP_API_URL || "/api",
    WS_URL: process.env.REACT_APP_WS_URL || "/ws",
    DEBUG_MODE: false,
    LOG_LEVEL: "error",
  },
};

const environment = process.env.NODE_ENV || "development";
export default config[environment];
