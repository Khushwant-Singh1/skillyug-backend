import { User as PrismaUser, UserType } from '@prisma/client';
import { JwtPayload } from 'jsonwebtoken';

declare global {
  namespace Express {
    interface User extends PrismaUser {
      // Additional fields can be added here as needed
      userType: UserType;
    }
  }
}

export interface UserWithPassword extends PrismaUser {
  password: string;
}

export interface UserJwtPayload extends JwtPayload {
  id: string;
  email: string; // Make email required as we validate it before creating the payload
  userType: UserType;
  [key: string]: unknown; // Allow additional properties
}
