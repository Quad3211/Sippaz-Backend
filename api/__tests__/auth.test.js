const request = require("supertest");

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
const bcrypt = require("bcrypt");

describe("Auth API Integration", () => {
  beforeEach(() => {
    mockQuery.mockReset();
  });

  it("POST /auth/register should create a new user", async () => {
    // Mock DB logic:
    // 1st query: check if exists (returns empty array)
    // 2nd query: insert user (returns true)
    mockQuery.mockResolvedValueOnce([[]]);
    mockQuery.mockResolvedValueOnce([ { insertId: 1 } ]);

    const res = await request(app)
      .post("/auth/register")
      .send({ email: "test@example.com", password: "password123", role: "customer" });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("success", true);
    expect(res.body).toHaveProperty("token");
    expect(res.body.user).toHaveProperty("id", 1);
  });

  it("POST /auth/login should return a JWT wrapper when successful", async () => {
    // Mock DB logic: returning a mocked hashed user
    const hash = await bcrypt.hash("password123", 1);
    mockQuery.mockResolvedValueOnce([
      [{ id: 1, email: "test@example.com", password: hash, role: "customer" }]
    ]);

    const res = await request(app)
      .post("/auth/login")
      .send({ email: "test@example.com", password: "password123" });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("token");
    expect(res.body.user).toHaveProperty("email", "test@example.com");
  });

  it("POST /auth/login should reject bad passwords", async () => {
    const hash = await bcrypt.hash("password123", 1);
    mockQuery.mockResolvedValueOnce([
      [{ id: 1, email: "test@example.com", password: hash, role: "customer" }]
    ]);

    const res = await request(app)
      .post("/auth/login")
      .send({ email: "test@example.com", password: "wrongpassword" });

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty("message", "Invalid email or password");
  });
});
