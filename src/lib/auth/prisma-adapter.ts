import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { PrismaClient, UserType } from "@prisma/client";
import { AdapterUser } from "next-auth/adapters";

export function CustomPrismaAdapter(p: PrismaClient) {
  const adapter = PrismaAdapter(p);
  
  return {
    ...adapter,
    // Override the getUser method to include userType and ensure type safety
    async getUser(id: string): Promise<AdapterUser | null> {
      const user = await p.user.findUnique({
        where: { id },
        select: {
          id: true,
          fullName: true,
          email: true,
          emailVerified: true,
          image: true,
          userType: true,
        },
      });
      
      if (!user || !user.email) return null;
      
      return {
        id: user.id,
        name: user.fullName || user.email.split('@')[0],
        email: user.email, // Ensured to be non-null
        emailVerified: user.emailVerified,
        image: user.image,
        userType: user.userType,
      } as AdapterUser & { userType: UserType };
    },
  };
}
