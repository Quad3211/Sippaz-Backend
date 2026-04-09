const request = require("supertest");

// Mock mysql2/promise before requiring server.js
jest.mock("mysql2/promise", () => {
  const mPool = {
    getConnection: jest.fn().mockResolvedValue({
      query: jest.fn().mockResolvedValue([]),
      release: jest.fn(),
    }),
    query: jest.fn().mockResolvedValue([]),
  };
  return {
    createPool: jest.fn(() => mPool),
  };
});

const app = require("../../server");

describe("Health API and Global Errors", () => {
  it("GET /health should return healthy status", async () => {
    const res = await request(app).get("/health");
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("status", "healthy");
  });

  it("GET /non-existent should return 404", async () => {
    const res = await request(app).get("/non-existent-route-123");
    expect(res.statusCode).toEqual(404);
    expect(res.body).toHaveProperty("message", "Endpoint not found");
  });
});
