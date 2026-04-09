const request = require("supertest");
const jwt = require("jsonwebtoken");

// Mock mysql2/promise before requiring server.js
const mockQuery = jest.fn();
jest.mock("mysql2/promise", () => {
  const mPool = {
    getConnection: jest.fn().mockResolvedValue({
      query: jest.fn().mockResolvedValue([]),
      release: jest.fn(),
    }),
    query: (...args) => mockQuery(...args),
  };
  return {
    createPool: jest.fn(() => mPool),
  };
});

const app = require("../../server");

describe("Items API Integration", () => {
  let adminToken;
  let customerToken;

  beforeAll(() => {
    adminToken = jwt.sign(
      { id: 1, email: "admin@example.com", role: "admin" },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "1h" }
    );
    customerToken = jwt.sign(
      { id: 2, email: "user@example.com", role: "customer" },
      process.env.JWT_SECRET || "fallback_secret",
      { expiresIn: "1h" }
    );
  });

  beforeEach(() => {
    mockQuery.mockReset();
  });

  it("GET /items should return a list of active items", async () => {
    mockQuery.mockResolvedValueOnce([
      [
        { id: 1, name: "Beer", price: "5.00", is_active: 1 },
        { id: 2, name: "Juice", price: "3.00", is_active: 1 }
      ]
    ]);

    const res = await request(app).get("/items");
    expect(res.statusCode).toEqual(200);
    expect(res.body.length).toBe(2);
    expect(res.body[0]).toHaveProperty("name", "Beer");
  });

  it("POST /items should succeed for an admin user", async () => {
    mockQuery.mockResolvedValueOnce([ { insertId: 3 } ]);

    const res = await request(app)
      .post("/items")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        name: "New Item",
        description: "Test Item",
        price: 9.99,
        quantity: 10,
        image_url: "",
        is_alcoholic: false
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("message", "Item created successfully");
  });

  it("POST /items should fail for a customer user", async () => {
    const res = await request(app)
      .post("/items")
      .set("Authorization", `Bearer ${customerToken}`)
      .send({
        name: "Customer Item",
        price: 9.99
      });

    expect(res.statusCode).toEqual(403);
    expect(res.body).toHaveProperty("message", "Admin access required");
  });

  it("POST /items should fail without a token", async () => {
    const res = await request(app)
      .post("/items")
      .send({
        name: "Hacker Item",
        price: 9.99
      });

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty("message", "Authentication required");
  });
});
