// api/routes/auth.routes.js
// Authentication routes: register and login

const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { schemas, validate } = require("../middleware/validate.middleware");

const SALT_ROUNDS = 10;
const { JWT_SECRET } = process.env;

// Rate limiter: max 20 auth requests per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: "Too many attempts, please try again later." },
});

/**
 * POST /auth/register
 * Creates a new user account with bcrypt-hashed password.
 */
router.post(
  "/register",
  authLimiter,
  validate(schemas.register),
  async (req, res) => {
    const { email, password } = req.body;
    const pool = req.app.locals.pool;

    try {
      console.log("Registration attempt:", email);

      const [existing] = await pool.query(
        "SELECT id FROM users WHERE email = ?",
        [email],
      );
      if (existing.length) {
        return res
          .status(400)
          .json({ success: false, message: "Email already registered" });
      }

      // Hash password before storage — never store plaintext passwords
      const hashed = await bcrypt.hash(password, SALT_ROUNDS);

      const [result] = await pool.query(
        "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
        [email, hashed, "customer"],
      );

      const userResponse = { id: result.insertId, email, role: "customer" };
      const token = jwt.sign(userResponse, JWT_SECRET, { expiresIn: "7d" });

      console.log("✓ User registered:", email);
      res.json({ success: true, user: userResponse, token });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ success: false, message: "Registration failed" });
    }
  },
);

/**
 * POST /auth/login
 * Authenticates user credentials and returns a signed JWT.
 */
router.post(
  "/login",
  authLimiter,
  validate(schemas.login),
  async (req, res) => {
    const { email, password } = req.body;
    const pool = req.app.locals.pool;

    try {
      console.log("Login attempt:", email);

      const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);

      if (!users.length) {
        // Use same message for both "not found" and "wrong password" to prevent enumeration
        return res
          .status(401)
          .json({ success: false, message: "Invalid email or password" });
      }

      const user = users[0];
      const valid = await bcrypt.compare(password, user.password);

      if (!valid) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid email or password" });
      }

      const userResponse = { id: user.id, email: user.email, role: user.role };
      const token = jwt.sign(userResponse, JWT_SECRET, { expiresIn: "7d" });

      console.log("✓ User logged in:", email);
      res.json({ success: true, user: userResponse, token });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ success: false, message: "Login failed" });
    }
  },
);

module.exports = router;
