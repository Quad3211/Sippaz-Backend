// backend/api/index.js - Serverless entry point
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Joi = require("joi");
const paypal = require("../paypal-api");
require("dotenv").config();

const app = express();

// ============================================
// ENVIRONMENT VARIABLES
// ============================================
const {
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  JWT_SECRET,
  MYSQL_HOST,
  MYSQL_USER,
  MYSQL_PASSWORD,
  MYSQL_DATABASE,
} = process.env;

const SALT_ROUNDS = 10;

// Use MYSQL_ vars if DB_ vars aren't set (for Vercel)
const dbConfig = {
  host: DB_HOST || MYSQL_HOST,
  user: DB_USER || MYSQL_USER,
  password: DB_PASSWORD || MYSQL_PASSWORD,
  database: DB_NAME || MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
};

// ============================================
// SECURITY & MIDDLEWARE
// ============================================
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);

app.use(
  cors({
    origin: true, // Allow all origins in production, or specify your frontend URL
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: "Too many attempts, please try again later." },
});

// ============================================
// DATABASE CONNECTION POOL
// ============================================
let pool;

function getPool() {
  if (!pool) {
    pool = mysql.createPool(dbConfig);
  }
  return pool;
}

// Initialize database tables
async function initDatabase() {
  try {
    const conn = await getPool().getConnection();
    console.log("✓ Database connected");

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

    await conn.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT PRIMARY KEY AUTO_INCREMENT,
        user_id INT,
        item_id INT NOT NULL,
        quantity INT NOT NULL,
        status VARCHAR(50) DEFAULT 'ordered',
        total_price DECIMAL(10,2) NOT NULL,
        ordered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paypal_order_id VARCHAR(255),
        capture_id VARCHAR(255),
        payment_status VARCHAR(50) DEFAULT 'pending',
        FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id)
      )
    `);

    console.log("✓ Database tables ready");
    conn.release();
  } catch (err) {
    console.error("✗ Database error:", err.message);
  }
}

// Initialize on first request
let initialized = false;
app.use(async (req, res, next) => {
  if (!initialized) {
    await initDatabase();
    initialized = true;
  }
  next();
});

// ============================================
// VALIDATION SCHEMAS
// ============================================
const schemas = {
  register: Joi.object({
    email: Joi.string().email().lowercase().trim().required(),
    password: Joi.string().min(6).max(128).required(),
  }),
  login: Joi.object({
    email: Joi.string().email().lowercase().trim().required(),
    password: Joi.string().required(),
  }),
  item: Joi.object({
    name: Joi.string().min(3).max(100).trim().required(),
    description: Joi.string().max(500).allow("").optional(),
    price: Joi.number().min(0).max(10000).required(),
    quantity: Joi.number().integer().min(0).max(10000).required(),
    imageUrl: Joi.string().max(5000000).allow("").optional(),
    isActive: Joi.boolean().default(true),
    isAlcoholic: Joi.boolean().default(false),
  }),
  order: Joi.object({
    itemId: Joi.number().integer().positive().required(),
    quantity: Joi.number().integer().min(1).max(100).required(),
  }),
};

const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true,
  });
  if (error) {
    return res.status(400).json({
      success: false,
      message: "Validation error",
      errors: error.details.map((d) => d.message),
    });
  }
  req.body = value;
  next();
};

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================
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

const optionalAuth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token) {
    try {
      const user = jwt.verify(token, JWT_SECRET);
      req.user = user;
    } catch (err) {
      // Ignore invalid tokens for optional auth
    }
  }
  next();
};

const isAdmin = (req, res, next) => {
  if (req.user?.role === "admin") {
    next();
  } else {
    res.status(403).json({ message: "Admin access required" });
  }
};

// ============================================
// HEALTH CHECK
// ============================================
app.get("/health", async (req, res) => {
  try {
    await getPool().query("SELECT 1");
    res.json({ status: "healthy", database: "connected" });
  } catch (error) {
    res.status(503).json({ status: "unhealthy", database: "disconnected" });
  }
});

// ============================================
// AUTH ROUTES
// ============================================
app.post(
  "/auth/register",
  authLimiter,
  validate(schemas.register),
  async (req, res) => {
    const { email, password } = req.body;

    try {
      const [existing] = await getPool().query(
        "SELECT id FROM users WHERE email = ?",
        [email],
      );

      if (existing.length) {
        return res.status(400).json({
          success: false,
          message: "Email already registered",
        });
      }

      const hashed = await bcrypt.hash(password, SALT_ROUNDS);

      const [result] = await getPool().query(
        "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
        [email, hashed, "customer"],
      );

      const userResponse = { id: result.insertId, email, role: "customer" };
      const token = jwt.sign(userResponse, JWT_SECRET, { expiresIn: "7d" });

      res.json({ success: true, user: userResponse, token });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ success: false, message: "Registration failed" });
    }
  },
);

app.post(
  "/auth/login",
  authLimiter,
  validate(schemas.login),
  async (req, res) => {
    const { email, password } = req.body;

    try {
      const [users] = await getPool().query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);

      if (!users.length) {
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

      res.json({ success: true, user: userResponse, token });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ success: false, message: "Login failed" });
    }
  },
);

// ============================================
// ITEMS ROUTES
// ============================================
app.get("/items", async (req, res) => {
  try {
    const [items] = await getPool().query(
      "SELECT id, name, description, price, quantity, image_url, is_alcoholic, created_at FROM items WHERE is_active = true ORDER BY created_at DESC",
    );
    res.json(items);
  } catch (error) {
    console.error("Error fetching items:", error);
    res.status(500).json({ message: "Failed to fetch items" });
  }
});

app.get("/items/:id", async (req, res) => {
  try {
    const [items] = await getPool().query("SELECT * FROM items WHERE id = ?", [
      req.params.id,
    ]);
    if (!items.length) {
      return res.status(404).json({ message: "Item not found" });
    }
    res.json(items[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch item" });
  }
});

app.get("/admin/items", authenticateToken, isAdmin, async (req, res) => {
  try {
    const [items] = await getPool().query(
      "SELECT * FROM items ORDER BY created_at DESC",
    );
    res.json(items);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch items" });
  }
});

app.post(
  "/items",
  authenticateToken,
  isAdmin,
  validate(schemas.item),
  async (req, res) => {
    const {
      name,
      description,
      price,
      quantity,
      imageUrl,
      isActive,
      isAlcoholic,
    } = req.body;

    try {
      const [result] = await getPool().query(
        "INSERT INTO items (name, description, price, quantity, image_url, is_active, is_alcoholic) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          name,
          description || "",
          price,
          quantity,
          imageUrl || "",
          isActive !== undefined ? isActive : true,
          isAlcoholic !== undefined ? isAlcoholic : false,
        ],
      );

      res.json({
        success: true,
        id: result.insertId,
        message: "Item created successfully",
      });
    } catch (error) {
      console.error("Error creating item:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to create item" });
    }
  },
);

app.put(
  "/items/:id",
  authenticateToken,
  isAdmin,
  validate(schemas.item),
  async (req, res) => {
    const {
      name,
      description,
      price,
      quantity,
      imageUrl,
      isActive,
      isAlcoholic,
    } = req.body;

    try {
      const [result] = await getPool().query(
        "UPDATE items SET name = ?, description = ?, price = ?, quantity = ?, image_url = ?, is_active = ?, is_alcoholic = ? WHERE id = ?",
        [
          name,
          description || "",
          price,
          quantity,
          imageUrl || "",
          isActive !== undefined ? isActive : true,
          isAlcoholic !== undefined ? isAlcoholic : false,
          req.params.id,
        ],
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Item not found" });
      }

      res.json({ success: true, message: "Item updated successfully" });
    } catch (error) {
      console.error("Error updating item:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to update item" });
    }
  },
);

app.delete("/items/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const [result] = await getPool().query("DELETE FROM items WHERE id = ?", [
      req.params.id,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Item not found" });
    }
    res.json({ success: true, message: "Item deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to delete item" });
  }
});

// ============================================
// ORDERS ROUTES
// ============================================
app.post("/orders", optionalAuth, validate(schemas.order), async (req, res) => {
  const { itemId, quantity } = req.body;
  const userId = req.user?.id || null;

  const connection = await getPool().getConnection();

  try {
    await connection.beginTransaction();

    const [items] = await connection.query(
      "SELECT * FROM items WHERE id = ? FOR UPDATE",
      [itemId],
    );

    if (!items.length) {
      await connection.rollback();
      return res.status(404).json({ message: "Item not found" });
    }

    const item = items[0];

    if (item.quantity < quantity) {
      await connection.rollback();
      return res.status(400).json({
        message: `Insufficient stock. Only ${item.quantity} available.`,
      });
    }

    const totalPrice = item.price * quantity;

    const [orderResult] = await connection.query(
      "INSERT INTO orders (user_id, item_id, quantity, total_price, status, payment_status) VALUES (?, ?, ?, ?, ?, ?)",
      [userId, itemId, quantity, totalPrice, "pending_payment", "pending"],
    );

    await connection.query(
      "UPDATE items SET quantity = quantity - ? WHERE id = ?",
      [quantity, itemId],
    );

    await connection.commit();

    res.json({
      success: true,
      orderId: orderResult.insertId,
      message: "Order placed successfully",
    });
  } catch (error) {
    await connection.rollback();
    console.error("Error creating order:", error);
    res.status(500).json({ success: false, message: "Failed to place order" });
  } finally {
    connection.release();
  }
});

app.get("/orders/mine", optionalAuth, async (req, res) => {
  try {
    let query, params;

    if (req.user?.id) {
      query = `
        SELECT orders.*, items.name as item_name, items.image_url, items.price as item_price
        FROM orders
        JOIN items ON orders.item_id = items.id
        WHERE orders.user_id = ?
        ORDER BY orders.ordered_at DESC
      `;
      params = [req.user.id];
    } else {
      query = `
        SELECT orders.*, items.name as item_name, items.image_url, items.price as item_price
        FROM orders
        JOIN items ON orders.item_id = items.id
        WHERE orders.user_id IS NULL
        ORDER BY orders.ordered_at DESC
        LIMIT 50
      `;
      params = [];
    }

    const [orders] = await getPool().query(query, params);
    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});

app.get("/orders/:id", optionalAuth, async (req, res) => {
  try {
    const [orders] = await getPool().query(
      `SELECT orders.*, items.name as item_name, items.image_url, items.price as item_price
       FROM orders
       JOIN items ON orders.item_id = items.id
       WHERE orders.id = ?`,
      [req.params.id]
    );

    if (!orders.length) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.json(orders[0]);
  } catch (error) {
    console.error("Error fetching order:", error);
    res.status(500).json({ message: "Failed to fetch order" });
  }
});

app.get("/admin/orders", authenticateToken, isAdmin, async (req, res) => {
  try {
    const [orders] = await getPool().query(`
      SELECT orders.*, users.email as user_email, items.name as item_name, items.image_url, items.price as item_price
      FROM orders
      LEFT JOIN users ON orders.user_id = users.id
      JOIN items ON orders.item_id = items.id
      ORDER BY orders.ordered_at DESC
    `);
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});

app.put("/orders/:id/status", authenticateToken, isAdmin, async (req, res) => {
  const { status } = req.body;

  if (!["ordered", "fulfilled", "cancelled"].includes(status)) {
    return res.status(400).json({ message: "Invalid status" });
  }

  try {
    const [result] = await getPool().query(
      "UPDATE orders SET status = ? WHERE id = ?",
      [status, req.params.id],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.json({ success: true, message: "Order status updated" });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Failed to update order status" });
  }
});

// ============================================
// PAYPAL ROUTES
// ============================================
app.post("/orders/:id/create-paypal-order", optionalAuth, async (req, res) => {
  const orderId = req.params.id;
  try {
    const [orders] = await getPool().query(
      "SELECT total_price FROM orders WHERE id = ?",
      [orderId],
    );

    if (!orders.length) {
      return res.status(404).json({ message: "Order not found" });
    }

    const order = orders[0];

    const { jsonResponse, httpStatusCode } = await paypal.createOrder(
      "USD",
      order.total_price,
    );

    if (httpStatusCode !== 201) {
      console.error("Failed to create PayPal order:", jsonResponse);
      return res.status(500).json({ message: "Failed to create PayPal order" });
    }

    await getPool().query("UPDATE orders SET paypal_order_id = ? WHERE id = ?", [
      jsonResponse.id,
      orderId,
    ]);

    res.status(201).json(jsonResponse);
  } catch (error) {
    console.error("Error creating PayPal order:", error);
    res.status(500).json({ message: "Failed to initiate PayPal checkout" });
  }
});

app.post("/orders/:id/capture-paypal-order", optionalAuth, async (req, res) => {
  const orderId = req.params.id;
  try {
    const [orders] = await getPool().query(
      "SELECT paypal_order_id FROM orders WHERE id = ?",
      [orderId],
    );

    if (!orders.length || !orders[0].paypal_order_id) {
      return res
        .status(404)
        .json({ message: "Order or PayPal transaction not found" });
    }

    const { paypal_order_id } = orders[0];

    const { jsonResponse, httpStatusCode } =
      await paypal.capturePayment(paypal_order_id);

    if (httpStatusCode !== 201) {
      console.error("Failed to capture PayPal order:", jsonResponse);
      return res.status(500).json({ message: "Failed to capture payment" });
    }

    await getPool().query(
      "UPDATE orders SET status = ?, payment_status = ?, capture_id = ? WHERE id = ?",
      [
        "ordered",
        "completed",
        jsonResponse.purchase_units[0].payments.captures[0].id,
        orderId,
      ],
    );

    res.json(jsonResponse);
  } catch (error) {
    console.error("Error capturing PayPal order:", error);
    res.status(500).json({ message: "Failed to capture payment" });
  }
});

// ============================================
// ERROR HANDLING
// ============================================
app.use((req, res) => res.status(404).json({ message: "Endpoint not found" }));
app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// Export for Vercel serverless
module.exports = app;