import { Prisma, User, UserType } from '@prisma/client';
import prisma from '../utils/prisma';
import { DatabaseError, NotFoundError } from '../utils/errors';

/**
 * Custom types for better type safety
 */
type UserWithPassword = User & { password: string };
type UserProfile = Omit<User, 'password' | 'otp' | 'passwordResetToken'>;
type SafeUser = Omit<User, 'password' | 'otp' | 'passwordResetToken' | 'passwordResetExpires'>;

/**
 * User Repository - Handles all database operations for users
 * Following the Repository pattern for separation of concerns
 */
export class UserRepository {
  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { email },
      });
    } catch (error) {
      throw new DatabaseError('Failed to find user by email', error);
    }
  }

  /**
   * Find user by ID
   */
  async findById(id: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { id },
      });
    } catch (error) {
      throw new DatabaseError('Failed to find user by ID', error);
    }
  }

  /**
   * Find user by ID or throw error if not found
   */
  async findByIdOrThrow(id: string): Promise<User> {
    const user = await this.findById(id);
    if (!user) {
      throw new NotFoundError('User');
    }
    return user;
  }

  /**
   * Find user by email with password
   */
  async findByEmailWithPassword(email: string): Promise<UserWithPassword | null> {
    try {
      const user = await prisma.user.findUnique({
        where: { email },
      });
      return user as UserWithPassword | null;
    } catch (error) {
      throw new DatabaseError('Failed to find user with password', error);
    }
  }

  /**
   * Find user by password reset token
   */
  async findByPasswordResetToken(token: string): Promise<User | null> {
    try {
      return await prisma.user.findFirst({
        where: {
          passwordResetToken: token,
          passwordResetExpires: {
            gt: new Date(),
          },
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to find user by reset token', error);
    }
  }

  /**
   * Create new user
   */
  async create(userData: Prisma.UserCreateInput): Promise<SafeUser> {
    try {
      const user = await prisma.user.create({
        data: userData,
      });
      
      // Return safe user data (without sensitive fields)
      const { password, otp, passwordResetToken, passwordResetExpires, ...safeUser } = user;
      return safeUser;
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new DatabaseError('User with this email already exists');
        }
      }
      throw new DatabaseError('Failed to create user', error);
    }
  }

  /**
   * Update user by ID
   */
  async updateById(id: string, data: Prisma.UserUpdateInput): Promise<User> {
    try {
      return await prisma.user.update({
        where: { id },
        data,
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new NotFoundError('User');
        }
      }
      throw new DatabaseError('Failed to update user', error);
    }
  }

  /**
   * Update user by email
   */
  async updateByEmail(email: string, data: Prisma.UserUpdateInput): Promise<User> {
    try {
      return await prisma.user.update({
        where: { email },
        data,
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new NotFoundError('User');
        }
      }
      throw new DatabaseError('Failed to update user', error);
    }
  }

  /**
   * Delete user by ID
   */
  async deleteById(id: string): Promise<User> {
    try {
      return await prisma.user.delete({
        where: { id },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new NotFoundError('User');
        }
      }
      throw new DatabaseError('Failed to delete user', error);
    }
  }

  /**
   * Check if user exists by email
   */
  async existsByEmail(email: string): Promise<boolean> {
    try {
      const user = await prisma.user.findUnique({
        where: { email },
        select: { id: true },
      });
      return !!user;
    } catch (error) {
      throw new DatabaseError('Failed to check user existence', error);
    }
  }

  /**
   * Update user password
   */
  async updatePassword(id: string, hashedPassword: string): Promise<User> {
    try {
      return await prisma.user.update({
        where: { id },
        data: { 
          password: hashedPassword,
          passwordResetToken: null,
          passwordResetExpires: null,
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to update password', error);
    }
  }

  /**
   * Set OTP for user
   */
  async setOtp(email: string, hashedOtp: string, expiresAt: Date): Promise<User> {
    try {
      return await prisma.user.update({
        where: { email },
        data: {
          otp: hashedOtp,
          otpExpires: expiresAt,
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to set OTP', error);
    }
  }

  /**
   * Clear OTP for user
   */
  async clearOtp(email: string): Promise<User> {
    try {
      return await prisma.user.update({
        where: { email },
        data: {
          otp: null,
          otpExpires: null,
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to clear OTP', error);
    }
  }

  /**
   * Verify user email
   */
  async verifyEmail(email: string): Promise<User> {
    try {
      return await prisma.user.update({
        where: { email },
        data: {
          isVerified: true,
          emailVerified: new Date(),
          otp: null,
          otpExpires: null,
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to verify email', error);
    }
  }

  /**
   * Set password reset token
   */
  async setPasswordResetToken(
    email: string, 
    token: string, 
    expiresAt: Date
  ): Promise<User> {
    try {
      return await prisma.user.update({
        where: { email },
        data: {
          passwordResetToken: token,
          passwordResetExpires: expiresAt,
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to set password reset token', error);
    }
  }

  /**
   * Get user profile (safe data only)
   */
  async getProfile(id: string): Promise<UserProfile | null> {
    try {
      const user = await prisma.user.findUnique({
        where: { id },
        select: {
          id: true,
          email: true,
          fullName: true,
          userType: true,
          isVerified: true,
          emailVerified: true,
          image: true,
          bio: true,
          createdAt: true,
          updatedAt: true,
          otpExpires: true,
          passwordResetExpires: true,
        },
      });
      return user;
    } catch (error) {
      throw new DatabaseError('Failed to get user profile', error);
    }
  }

  /**
   * Get paginated users (admin functionality)
   */
  async findMany(
    page: number = 1,
    limit: number = 10,
    filters?: {
      userType?: UserType;
      isVerified?: boolean;
    }
  ): Promise<{ users: SafeUser[]; total: number }> {
    try {
      const skip = (page - 1) * limit;
      const where: Prisma.UserWhereInput = {};

      if (filters?.userType) {
        where.userType = filters.userType;
      }
      
      if (typeof filters?.isVerified === 'boolean') {
        where.isVerified = filters.isVerified;
      }

      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where,
          skip,
          take: limit,
          orderBy: { createdAt: 'desc' },
        }),
        prisma.user.count({ where }),
      ]);

      // Remove sensitive fields
      const safeUsers = users.map(user => {
        const { password, otp, passwordResetToken, passwordResetExpires, ...safeUser } = user;
        return safeUser;
      });

      return { users: safeUsers, total };
    } catch (error) {
      throw new DatabaseError('Failed to fetch users', error);
    }
  }
}

// Export singleton instance
export const userRepository = new UserRepository();
