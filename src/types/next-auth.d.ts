import { UserType } from '@prisma/client';
import { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  /**
   * Extend the built-in session types
   */
  interface Session {
    user: {
      id: string;
      userType: UserType;
    } & DefaultSession['user']
  }

  /**
   * Extend the built-in user types
   */
  interface User {
    userType: UserType;
  }
}

declare module 'next-auth/jwt' {
  /**
   * Extend the built-in JWT types
   */
  interface JWT {
    userType: UserType;
  }
}
