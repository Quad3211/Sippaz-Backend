// backend/server.js — Entry point for the Sippaz Vibez REST API
// Routes are now modularized into api/routes/ for cleaner separation of concerns

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const helmet = require("helmet");
require("dotenv").config();

const app = express();

// ============================================
// ENVIRONMENT VARIABLES
// ============================================
const { DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, PORT = 3000 } = process.env;

// ============================================
// SECURITY MIDDLEWARE
// ============================================
// Helmet sets secure HTTP headers
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);

// CORS — restrict allowed origins to known frontend URLs
app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        "http://localhost:4200",
        "http://localhost:3000",
        process.env.FRONTEND_URL, // Production frontend URL from .env
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("Blocked by CORS:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// Body parsers — limit to 10mb to prevent oversized payloads
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// ============================================
// DATABASE CONNECTION POOL
// ============================================
const pool = process.env.DATABASE_URL
  ? mysql.createPool({
      uri: process.env.DATABASE_URL,
      waitForConnections: true,
      connectionLimit: 10,
    })
  : mysql.createPool({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASSWORD,
      database: DB_NAME,
      port: process.env.DB_PORT || 3306,
      waitForConnections: true,
      connectionLimit: 10,
    });

// Make pool available to all route handlers via app.locals
app.locals.pool = pool;

// ============================================
// DATABASE INITIALIZATION
// ============================================
(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✓ Database connected");

    // Users table — stores accounts; passwords are bcrypt-hashed
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'customer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email)
      )
    `);

    // Items table — the product catalogue
    await conn.query(`
      CREATE TABLE IF NOT EXISTS items (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        quantity INT DEFAULT 0,
        image_url LONGTEXT,
        is_active BOOLEAN DEFAULT true,
        is_alcoholic BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Orders table — links users to items, with FK and payment fields
    await conn.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT,
        item_id INT NOT NULL,
        quantity INT NOT NULL,
        status VARCHAR(50) DEFAULT 'ordered',
        payment_status VARCHAR(50) DEFAULT 'pending',
        total_price DECIMAL(10,2) NOT NULL,
        paypal_order_id VARCHAR(255),
        capture_id VARCHAR(255),
        ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id)
      )
    `);

    console.log("✓ Database tables ready");
    conn.release();
  } catch (err) {
    console.error("✗ Database init error:", err);
    process.exit(1);
  }
})();

// ============================================
// ROUTE MODULES
// ============================================
const authRoutes = require("./api/routes/auth.routes");
const itemsRoutes = require("./api/routes/items.routes");
const ordersRoutes = require("./api/routes/orders.routes");

// Health check endpoint
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "healthy", database: "connected" });
  } catch (error) {
    res.status(503).json({ status: "unhealthy", database: "disconnected" });
  }
});

// Mount routers at their base paths
app.use("/auth", authRoutes);
app.use("/items", itemsRoutes);
app.use("/orders", ordersRoutes);

// Admin routes — served from the same modular routers but require the
// AdminGuard on the frontend (Angular) and authenticateToken + isAdmin
// inside each route handler. We do NOT re-mount here to avoid bypassing auth.
// /admin/items and /admin/orders are declared inside items.routes.js and
// orders.routes.js respectively (e.g. router.get("/admin/all", ...)).

// ============================================
// GLOBAL ERROR HANDLING
// ============================================
// 404 — unknown route
app.use((req, res) => res.status(404).json({ message: "Endpoint not found" }));

// 500 — unhandled errors (try/catch in routes handle most cases)
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log("=".repeat(50));
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 API: http://localhost:${PORT}`);
  console.log(`🔓 Store & Orders: Public access`);
  console.log(`🔐 Admin routes: JWT required`);
  console.log("=".repeat(50));
});
