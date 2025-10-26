import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';

/**
 * Rate limiting middleware for authentication endpoints
 * Prevents brute force attacks and abuse
 */

// General rate limiter for auth endpoints
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: {
    error: 'Too many authentication attempts. Please try again in 15 minutes.',
    rateLimitExceeded: true,
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      error: 'Too many authentication attempts. Please try again in 15 minutes.',
      rateLimitExceeded: true,
    });
  },
});

// Stricter rate limiter for login attempts
export const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  message: {
    error: 'Too many login attempts. Please try again in 15 minutes.',
    rateLimitExceeded: true,
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    console.warn(`Rate limit exceeded for login from IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many login attempts. Please try again in 15 minutes.',
      rateLimitExceeded: true,
    });
  },
});

// Rate limiter for OTP requests (registration, resend)
export const otpRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // Limit each IP to 3 OTP requests per 5 minutes
  message: {
    error: 'Too many OTP requests. Please try again in 5 minutes.',
    rateLimitExceeded: true,
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    console.warn(`OTP rate limit exceeded from IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many OTP requests. Please try again in 5 minutes.',
      rateLimitExceeded: true,
    });
  },
});

// Rate limiter for password reset requests
export const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 password reset requests per hour
  message: {
    error: 'Too many password reset requests. Please try again in 1 hour.',
    rateLimitExceeded: true,
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    console.warn(`Password reset rate limit exceeded from IP: ${req.ip}`);
    res.status(429).json({
      error: 'Too many password reset requests. Please try again in 1 hour.',
      rateLimitExceeded: true,
    });
  },
});

/**
 * Generic rate limiter factory
 * Creates a rate limiter with custom configuration
 */
export const rateLimiterMiddleware = (options: {
  windowMs?: number;
  max?: number;
  message?: Record<string, unknown>;
}) => {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes default
    max: options.max || 100, // 100 requests default
    message: options.message || {
      error: 'Too many requests. Please try again later.',
      rateLimitExceeded: true,
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req: Request, res: Response) => {
      console.warn(`Rate limit exceeded from IP: ${req.ip}`);
      res.status(429).json(options.message || {
        error: 'Too many requests. Please try again later.',
        rateLimitExceeded: true,
      });
    },
  });
};
