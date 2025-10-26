import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserType } from '@prisma/client';
import { userRepository } from '../repositories/user.repository';
import { AuthenticationError, AuthorizationError } from '../utils/errors';

// JWT payload interface matching the token structure
interface JwtPayload extends jwt.JwtPayload {
  id: string;
  email: string;
  userType: UserType;
}

// Extended Request interface to include authenticated user
export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

// Async handler wrapper to catch errors in async functions
type AsyncRequestHandler = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => Promise<unknown>;

export const asyncHandler = (fn: AsyncRequestHandler) => 
  (req: AuthenticatedRequest, res: Response, next: NextFunction) => 
    Promise.resolve(fn(req, res, next)).catch(next);

/**
 * Authentication middleware
 * Validates JWT token and attaches user to request
 */
export const protect = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  let token: string | undefined;

  // 1) Check for token in Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    throw new AuthenticationError('You are not logged in! Please log in to get access.');
  }

  // 2) Verify the token
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in the environment variables.');
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // 3) Validate decoded payload structure
    if (typeof decoded === 'string') {
      throw new AuthenticationError('Invalid token format');
    }
    
    const payload = decoded as JwtPayload;
    
    // Validate required fields
    if (!payload.id || !payload.email || !payload.userType) {
      throw new AuthenticationError('Invalid token payload');
    }

    // 4) Optional: Verify user still exists in database
    if (payload.id) {
      const currentUser = await userRepository.findById(payload.id);
      if (!currentUser) {
        throw new AuthenticationError('The user belonging to this token no longer exists');
      }
      
      // Check if user is still verified
      if (!currentUser.isVerified) {
        throw new AuthenticationError('User account is not verified');
      }
    }
    
    // 5) Attach user to request
    req.user = payload;
    
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new AuthenticationError('Invalid token. Please log in again.');
    }
    if (error instanceof jwt.TokenExpiredError) {
      throw new AuthenticationError('Token has expired. Please log in again.');
    }
    throw error;
  }
});

/**
 * Role-based access control middleware
 * Restricts access to specific user types
 */
export const restrictTo = (...allowedUserTypes: UserType[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AuthenticationError('You are not logged in! Please log in to get access.');
    }

    const userType = req.user.userType;
    
    if (!allowedUserTypes.includes(userType)) {
      throw new AuthorizationError(`Access denied. Required user type: ${allowedUserTypes.join(' or ')}`);
    }

    next();
  };
};

/**
 * Optional authentication middleware
 * Attaches user to request if token is present, but doesn't require it
 */
export const optionalAuth = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  let token: string | undefined;

  // Check for token in Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(); // Continue without user
  }

  // Verify the token if present
  if (!process.env.JWT_SECRET) {
    return next(); // Continue without user if JWT_SECRET not configured
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (typeof decoded !== 'string') {
      const payload = decoded as JwtPayload;
      
      if (payload.id && payload.email && payload.userType) {
        // Verify user still exists
        const currentUser = await userRepository.findById(payload.id);
        if (currentUser && currentUser.isVerified) {
          req.user = payload;
        }
      }
    }
  } catch (error) {
    // Continue without user if token is invalid
    console.log('Optional auth failed:', error);
  }

  next();
});

/**
 * Check if current user owns a resource
 */
export const checkResourceOwnership = (userIdField: string = 'userId') => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AuthenticationError('Authentication required');
    }

    const resourceUserId = req.params[userIdField] || req.body[userIdField];
    
    if (resourceUserId && resourceUserId !== req.user.id && req.user.userType !== 'ADMIN') {
      throw new AuthorizationError('You can only access your own resources');
    }

    next();
  };
};
