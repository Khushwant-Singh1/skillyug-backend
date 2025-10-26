import { CustomPrismaAdapter } from "../lib/auth/prisma-adapter";
import prisma from "../utils/prisma";
import CredentialsProvider from "next-auth/providers/credentials";
import { UserType } from "@prisma/client";
import bcrypt from "bcrypt";
import { z } from "zod";
import { DefaultSession, NextAuthOptions } from "next-auth";
import { JWT } from "next-auth/jwt";

// Extend the built-in session types
declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      userType: UserType;
    } & DefaultSession['user'];
  }

  interface User {
    userType: UserType;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    userType: UserType;
  }
}

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const signupSchema = z.object({
  fullName: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
  userType: z.enum(['STUDENT', 'MENTOR']),
});

export const authOptions: NextAuthOptions = {
  adapter: CustomPrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        try {
          const { email, password } = loginSchema.parse(credentials);

          const user = await prisma.user.findUnique({
            where: { email },
          });

          if (!user || !user.password) {
            return null;
          }

          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (!passwordsMatch) {
            return null;
          }
          
          return {
            id: user.id,
            name: user.fullName,
            email: user.email,
            image: user.image,
            userType: user.userType,
          };
        } catch (error) {
          console.error("Authorization Error:", error);
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }: { token: JWT; user?: { id: string; userType: UserType } }) {
      if (user) {
        token.sub = user.id;
        token.userType = user.userType;
      }
      return token;
    },
    async session({ session, token }: { session: DefaultSession & { user: { id?: string; userType?: UserType } }; token: JWT }) {
      if (token && session.user) {
        session.user.id = token.sub as string;
        session.user.userType = token.userType as UserType;
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
  },
  session: {
    strategy: "jwt",
  },
  secret: process.env.AUTH_SECRET,
};
