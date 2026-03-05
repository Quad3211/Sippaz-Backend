// api/middleware/validate.middleware.js
// Joi validation schemas and reusable validator middleware

const Joi = require("joi");

/**
 * Centralized Joi validation schemas for all routes.
 */
const schemas = {
  /** /auth/register and /auth/login body schema */
  register: Joi.object({
    email: Joi.string().email().lowercase().trim().required(),
    password: Joi.string().min(6).max(128).required(),
  }),

  login: Joi.object({
    email: Joi.string().email().lowercase().trim().required(),
    password: Joi.string().required(),
  }),

  /** POST/PUT /items body schema */
  item: Joi.object({
    name: Joi.string().min(3).max(100).trim().required(),
    description: Joi.string().max(500).allow("").optional(),
    price: Joi.number().min(0).max(10000).required(),
    quantity: Joi.number().integer().min(0).max(10000).required(),
    imageUrl: Joi.string().max(5000000).allow("").optional(),
    isActive: Joi.boolean().default(true),
    isAlcoholic: Joi.boolean().default(false),
  }),

  /** POST /orders body schema */
  order: Joi.object({
    itemId: Joi.number().integer().positive().required(),
    quantity: Joi.number().integer().min(1).max(100).required(),
  }),
};

/**
 * validate — Factory that returns an Express middleware for Joi validation.
 * @param {Joi.Schema} schema - The schema to validate req.body against.
 */
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

  req.body = value; // Replace body with sanitized/validated value
  next();
};

module.exports = { schemas, validate };
