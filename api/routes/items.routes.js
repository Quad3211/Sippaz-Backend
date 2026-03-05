// api/routes/items.routes.js
// CRUD routes for the items (products) resource

const express = require("express");
const router = express.Router();
const { authenticateToken, isAdmin } = require("../middleware/auth.middleware");
const { schemas, validate } = require("../middleware/validate.middleware");

/**
 * GET /items
 * Public — returns all active items for display in the store.
 */
router.get("/", async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const [items] = await pool.query(
      "SELECT id, name, description, price, quantity, image_url, is_alcoholic, created_at FROM items WHERE is_active = true ORDER BY created_at DESC",
    );
    res.json(items);
  } catch (error) {
    console.error("Error fetching items:", error);
    res.status(500).json({ message: "Failed to fetch items" });
  }
});

/**
 * GET /items/:id
 * Public — returns a single item by ID.
 */
router.get("/:id", async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const [items] = await pool.query("SELECT * FROM items WHERE id = ?", [
      req.params.id,
    ]);
    if (!items.length)
      return res.status(404).json({ message: "Item not found" });
    res.json(items[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch item" });
  }
});

/**
 * GET /admin/items
 * Admin only — returns all items including inactive ones.
 */
router.get("/admin/all", authenticateToken, isAdmin, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const [items] = await pool.query(
      "SELECT * FROM items ORDER BY created_at DESC",
    );
    res.json(items);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch items" });
  }
});

/**
 * POST /items
 * Admin only — creates a new item.
 */
router.post(
  "/",
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
    const pool = req.app.locals.pool;

    try {
      const [result] = await pool.query(
        "INSERT INTO items (name, description, price, quantity, image_url, is_active, is_alcoholic) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          name,
          description || "",
          price,
          quantity,
          imageUrl || "",
          isActive ?? true,
          isAlcoholic ?? false,
        ],
      );
      console.log("✓ Item created:", name);
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

/**
 * PUT /items/:id
 * Admin only — updates an existing item by ID.
 */
router.put(
  "/:id",
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
    const pool = req.app.locals.pool;

    try {
      const [result] = await pool.query(
        "UPDATE items SET name = ?, description = ?, price = ?, quantity = ?, image_url = ?, is_active = ?, is_alcoholic = ? WHERE id = ?",
        [
          name,
          description || "",
          price,
          quantity,
          imageUrl || "",
          isActive ?? true,
          isAlcoholic ?? false,
          req.params.id,
        ],
      );
      if (result.affectedRows === 0)
        return res.status(404).json({ message: "Item not found" });

      console.log("✓ Item updated:", name);
      res.json({ success: true, message: "Item updated successfully" });
    } catch (error) {
      console.error("Error updating item:", error);
      res
        .status(500)
        .json({ success: false, message: "Failed to update item" });
    }
  },
);

/**
 * DELETE /items/:id
 * Admin only — deletes an item by ID.
 */
router.delete("/:id", authenticateToken, isAdmin, async (req, res) => {
  const pool = req.app.locals.pool;
  try {
    const [result] = await pool.query("DELETE FROM items WHERE id = ?", [
      req.params.id,
    ]);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: "Item not found" });
    res.json({ success: true, message: "Item deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to delete item" });
  }
});

module.exports = router;
