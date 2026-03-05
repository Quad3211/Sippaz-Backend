// api/routes/orders.routes.js
// Order management routes: create, read, status update, and PayPal integration

const express = require("express");
const router = express.Router();
const paypal = require("../../paypal-api");
const {
  authenticateToken,
  optionalAuth,
  isAdmin,
} = require("../middleware/auth.middleware");
const { schemas, validate } = require("../middleware/validate.middleware");

/**
 * POST /orders
 * Creates a new order (guest or authenticated user).
 * Uses a transaction to ensure atomic stock decrement + order creation.
 */
router.post("/", optionalAuth, validate(schemas.order), async (req, res) => {
  const { itemId, quantity } = req.body;
  const userId = req.user?.id || null; // null for guest orders
  const pool = req.app.locals.pool;
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    // Lock item row for update to prevent race conditions
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
      return res
        .status(400)
        .json({
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

    console.log(
      `✓ Order created: #${orderResult.insertId}${userId ? ` for user #${userId}` : " (guest)"}`,
    );
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

/**
 * GET /orders/mine
 * Returns the authenticated user's orders, or recent guest orders if not logged in.
 */
router.get("/mine", optionalAuth, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    let query, params;

    if (req.user?.id) {
      // Logged-in user — return their specific orders
      query = `
        SELECT orders.*, items.name as item_name, items.image_url, items.price as item_price
        FROM orders
        JOIN items ON orders.item_id = items.id
        WHERE orders.user_id = ?
        ORDER BY orders.ordered_at DESC
      `;
      params = [req.user.id];
    } else {
      // Guest — return last 50 guest orders
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

    const [orders] = await pool.query(query, params);
    res.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});

/**
 * GET /admin/orders
 * Admin only — returns all orders with user and item details.
 */
router.get("/admin/all", authenticateToken, isAdmin, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const [orders] = await pool.query(`
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

/**
 * PUT /orders/:id/status
 * Admin only — updates the status of an order.
 */
router.put("/:id/status", authenticateToken, isAdmin, async (req, res) => {
  const { status } = req.body;
  const pool = req.app.locals.pool;

  if (!["ordered", "fulfilled", "cancelled"].includes(status)) {
    return res.status(400).json({ message: "Invalid status" });
  }

  try {
    const [result] = await pool.query(
      "UPDATE orders SET status = ? WHERE id = ?",
      [status, req.params.id],
    );
    if (result.affectedRows === 0)
      return res.status(404).json({ message: "Order not found" });
    res.json({ success: true, message: "Order status updated" });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Failed to update order status" });
  }
});

/**
 * POST /orders/:id/create-paypal-order
 * Creates a PayPal order linked to an internal order.
 */
router.post("/:id/create-paypal-order", optionalAuth, async (req, res) => {
  const orderId = req.params.id;
  const pool = req.app.locals.pool;

  try {
    const [orders] = await pool.query(
      "SELECT total_price FROM orders WHERE id = ?",
      [orderId],
    );
    if (!orders.length)
      return res.status(404).json({ message: "Order not found" });

    const { jsonResponse, httpStatusCode } = await paypal.createOrder(
      "USD",
      orders[0].total_price,
    );
    if (httpStatusCode !== 201) {
      return res.status(500).json({ message: "Failed to create PayPal order" });
    }

    await pool.query("UPDATE orders SET paypal_order_id = ? WHERE id = ?", [
      jsonResponse.id,
      orderId,
    ]);
    res.status(201).json(jsonResponse);
  } catch (error) {
    console.error("Error creating PayPal order:", error);
    res.status(500).json({ message: "Failed to initiate PayPal checkout" });
  }
});

/**
 * POST /orders/:id/capture-paypal-order
 * Captures a PayPal payment and marks the order as paid.
 */
router.post("/:id/capture-paypal-order", optionalAuth, async (req, res) => {
  const orderId = req.params.id;
  const pool = req.app.locals.pool;

  try {
    const [orders] = await pool.query(
      "SELECT paypal_order_id FROM orders WHERE id = ?",
      [orderId],
    );
    if (!orders.length || !orders[0].paypal_order_id) {
      return res
        .status(404)
        .json({ message: "Order or PayPal transaction not found" });
    }

    const { jsonResponse, httpStatusCode } = await paypal.capturePayment(
      orders[0].paypal_order_id,
    );
    if (httpStatusCode !== 201) {
      return res.status(500).json({ message: "Failed to capture payment" });
    }

    await pool.query(
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

module.exports = router;
