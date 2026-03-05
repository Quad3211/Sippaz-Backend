// api/middleware/auth.middleware.js
// Shared authentication and authorization middleware for all Express routes

const jwt = require("jsonwebtoken");
const { JWT_SECRET } = process.env;

/**
 * authenticateToken — Verifies the JWT Bearer token in the Authorization header.
 * Returns 401 if no token, 403 if invalid/expired.
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Authentication required" });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

/**
 * optionalAuth — Attempts to verify JWT but continues even if no token is present.
 * Used for routes accessible to both guests and authenticated users.
 */
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      req.user = user;
    } catch (err) {
      // Silently ignore invalid tokens for optional auth
    }
  }
  next();
};

/**
 * isAdmin — Role-based access control middleware.
 * Must be used after authenticateToken. Allows only users with role 'admin'.
 */
const isAdmin = (req, res, next) => {
  if (req.user?.role === "admin") {
    next();
  } else {
    res.status(403).json({ message: "Admin access required" });
  }
};

module.exports = { authenticateToken, optionalAuth, isAdmin };
