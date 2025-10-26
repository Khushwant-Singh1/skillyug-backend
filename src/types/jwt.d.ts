import { UserType } from '@prisma/client';

declare global {
  namespace Express {
    interface User {
      id: string;
      email: string | null;
      userType: UserType;
    }
  }

  namespace NodeJS {
    interface ProcessEnv {
      JWT_SECRET: string;
      JWT_EXPIRES_IN?: string;
    }
  }
}

export interface JwtPayload {
  id: string;
  email: string | null;
  userType: UserType;
  iat?: number;
  exp?: number;
}

// Extend the JWT SignOptions to include our custom options
declare module 'jsonwebtoken' {
  export interface SignOptions {
    expiresIn?: string | number;
  }
}
