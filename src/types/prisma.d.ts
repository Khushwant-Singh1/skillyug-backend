import { User as _User } from '@prisma/client';

declare global {
   
  namespace Prisma {
     
    interface UserCreateInput {
      password?: string;
    }

     
    interface UserSelect {
      password?: boolean;
    }
  }
}

export {};
