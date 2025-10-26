#!/usr/bin/env tsx

/**
 * Enterprise Admin Creation Script for Skillyug 2.0
 * * This script creates a super admin user with full system privileges.
 * Designed for production environments with comprehensive error handling,
 * logging, and security best practices.
 * * @author Skillyug Development Team
 * @version 2.0.0
 * @since 2024
 */

import { PrismaClient, UserType, AdminActionType } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';

// ========================================
// CONFIGURATION & VALIDATION
// ========================================

const prisma = new PrismaClient({
  log: ['query', 'info', 'warn', 'error'],
});

// Environment validation schema
const envSchema = z.object({
  ADMIN_EMAIL: z.string().email('Invalid email format'),
  ADMIN_PASSWORD: z.string().min(12, 'Password must be at least 12 characters'),
  ADMIN_FULL_NAME: z.string().min(2, 'Full name must be at least 2 characters').optional(),
  ADMIN_BIO: z.string().optional(),
  ADMIN_IMAGE_URL: z.string().url('Invalid image URL').optional(),
  FORCE_UPDATE: z.enum(['true', 'false']).optional(),
  DRY_RUN: z.enum(['true', 'false']).optional(),
});

// Admin creation data schema (for future use)
const _adminDataSchema = z.object({
  email: z.string().email(),
  password: z.string().min(12),
  fullName: z.string().min(2),
  bio: z.string().optional(),
  imageUrl: z.string().url().optional(),
});

// ========================================
// TYPES & INTERFACES
// ========================================

interface AdminCredentials {
  email: string;
  password: string;
  fullName: string;
  bio?: string;
  imageUrl?: string;
}

interface AdminCreationResult {
  success: boolean;
  user?: {
    id: string;
    email: string;
    fullName: string;
    userType: UserType;
    createdAt: Date;
  };
  error?: string;
  warnings?: string[];
}

interface ScriptConfig {
  dryRun: boolean;
  forceUpdate: boolean;
  logLevel: 'info' | 'debug' | 'warn' | 'error';
}

interface AdminUserData {
  email: string;
  fullName: string;
  password: string;
  userType: UserType;
  emailVerified: Date;
  isVerified: boolean;
  bio: string;
  image: string;
  createdAt: Date;
  updatedAt: Date;
}

type LogData = Record<string, unknown> | string[] | string | unknown;

// ========================================
// UTILITY FUNCTIONS
// ========================================

class Logger {
  private config: ScriptConfig;

  constructor(config: ScriptConfig) {
    this.config = config;
  }

  private formatMessage(level: string, message: string, data?: LogData): string {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;
    
    if (data) {
      return `${prefix} ${message}\n${JSON.stringify(data, null, 2)}`;
    }
    return `${prefix} ${message}`;
  }

  info(message: string, data?: LogData): void {
    console.log(this.formatMessage('info', message, data));
  }

  debug(message: string, data?: LogData): void {
    if (this.config.logLevel === 'debug') {
      console.log(this.formatMessage('debug', message, data));
    }
  }

  warn(message: string, data?: LogData): void {
    console.warn(this.formatMessage('warn', message, data));
  }

  error(message: string, data?: LogData): void {
    console.error(this.formatMessage('error', message, data));
  }

  success(message: string, data?: LogData): void {
    console.log(`✅ ${this.formatMessage('success', message, data)}`);
  }
}

class SecurityValidator {
  static validatePassword(password: string): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (password.length < 12) {
      errors.push('Password must be at least 12 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  static validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}

// ========================================
// CORE ADMIN CREATION LOGIC
// ========================================

class AdminCreator {
  private prisma: PrismaClient;
  private logger: Logger;
  private config: ScriptConfig;

  constructor(prisma: PrismaClient, logger: Logger, config: ScriptConfig) {
    this.prisma = prisma;
    this.logger = logger;
    this.config = config;
  }

  async createAdmin(credentials: AdminCredentials): Promise<AdminCreationResult> {
    const warnings: string[] = [];
    
    try {
      this.logger.info('Starting admin creation process', { 
        email: credentials.email,
        dryRun: this.config.dryRun 
      });

      // 1. Validate credentials
      const validation = this.validateCredentials(credentials);
      if (!validation.isValid) {
        return {
          success: false,
          error: `Validation failed: ${validation.errors.join(', ')}`
        };
      }

      // 2. Check if admin already exists
      const existingAdmin = await this.checkExistingAdmin(credentials.email);
      if (existingAdmin && !this.config.forceUpdate) {
        return {
          success: false,
          error: 'Admin user already exists. Use FORCE_UPDATE=true to update.',
          warnings: ['Admin user already exists']
        };
      }

      if (existingAdmin && this.config.forceUpdate) {
        warnings.push('Updating existing admin user');
        this.logger.warn('Updating existing admin user', { 
          id: existingAdmin.id,
          email: existingAdmin.email 
        });
      }

      // 3. Hash password
      this.logger.debug('Hashing password...');
      const hashedPassword = await bcrypt.hash(credentials.password, 12);

      // 4. Prepare admin data
      const adminData: AdminUserData = {
        email: credentials.email,
        fullName: credentials.fullName,
        password: hashedPassword, // <- Ensure your schema has this field
        userType: UserType.ADMIN,
        emailVerified: new Date(),
        isVerified: true, // Set admin as verified
        bio: credentials.bio || 'System Administrator',
        image: credentials.imageUrl || '/Pics/GroupPic.jpg',
        createdAt: existingAdmin?.createdAt || new Date(),
        updatedAt: new Date(),
      };

      // 5. Create or update admin user
      if (this.config.dryRun) {
        this.logger.info('DRY RUN: Would create/update admin user', adminData);
        return {
          success: true,
          user: {
            id: 'auto-generated-id', // Will be auto-generated by database
            email: adminData.email,
            fullName: adminData.fullName,
            userType: adminData.userType,
            createdAt: adminData.createdAt,
          },
          warnings
        };
      }

      const adminUser = await this.saveAdminUser(adminData, hashedPassword);
      
      // 6. Log admin action
      await this.logAdminAction(adminUser.id, existingAdmin ? 'UPDATE' : 'CREATE');

      // 7. Update NextAuth configuration
      await this.updateNextAuthConfig(adminUser, hashedPassword);

      this.logger.success('Admin user created/updated successfully', {
        id: adminUser.id,
        email: adminUser.email,
        userType: adminUser.userType
      });

      return {
        success: true,

        user: {
          id: adminUser.id,
          email: adminUser.email ?? '',
          fullName: adminUser.fullName ?? '',
          userType: adminUser.userType,
          createdAt: adminUser.createdAt,
        },
        warnings
      };

    } catch (error) {
      this.logger.error('Failed to create admin user', { error: error instanceof Error ? error.message : String(error) });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  private validateCredentials(credentials: AdminCredentials): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate email
    if (!SecurityValidator.validateEmail(credentials.email)) {
      errors.push('Invalid email format');
    }

    // Validate password
    const passwordValidation = SecurityValidator.validatePassword(credentials.password);
    if (!passwordValidation.isValid) {
      errors.push(...passwordValidation.errors);
    }

    // Validate full name
    if (!credentials.fullName || credentials.fullName.trim().length < 2) {
      errors.push('Full name must be at least 2 characters long');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  private async checkExistingAdmin(email: string) {
    return await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        fullName: true,
        userType: true,
        createdAt: true,
        updatedAt: true,
      }
    });
  }

  private async saveAdminUser(adminData: AdminUserData, _hashedPassword: string) {
    return await this.prisma.user.upsert({
      where: { email: adminData.email },
      update: {
        fullName: adminData.fullName,
        password: adminData.password, // <- Ensure your schema has this field
        userType: adminData.userType,
        emailVerified: adminData.emailVerified,
        isVerified: adminData.isVerified,
        bio: adminData.bio,
        image: adminData.image,
        updatedAt: adminData.updatedAt,
      },
      create: {
        email: adminData.email,
        fullName: adminData.fullName,
        password: adminData.password, // <- Ensure your schema has this field
        userType: adminData.userType,
        emailVerified: adminData.emailVerified,
        isVerified: adminData.isVerified,
        bio: adminData.bio,
        image: adminData.image,
        createdAt: adminData.createdAt,
        updatedAt: adminData.updatedAt,
      }
    });
  }

  private async logAdminAction(adminId: string, action: 'CREATE' | 'UPDATE') {
    await this.prisma.adminAction.create({
      data: {
        adminId,
        action: action === 'CREATE' ? AdminActionType.CREATE : AdminActionType.UPDATE,
        targetType: 'user',
        targetId: adminId,
        description: `Admin user ${action.toLowerCase()}d via enterprise script`,
        metadata: {
          scriptVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          environment: process.env.NODE_ENV || 'development',
          createdBy: 'system',
        }
      }
    });
  }

  private async updateNextAuthConfig(adminUser: { id: string; email: string | null; fullName: string | null; image: string | null }, hashedPassword: string) {
    try {
      const authFilePath = path.join(__dirname, '../../frontend-nextjs/src/lib/auth.ts');
      
      if (!fs.existsSync(authFilePath)) {
        this.logger.warn('NextAuth auth.ts file not found, skipping NextAuth update');
        return;
      }

      this.logger.debug('Updating NextAuth configuration...');
      
      let authContent = fs.readFileSync(authFilePath, 'utf8');
      
      // Check if admin user already exists in NextAuth
      const existingAdminRegex = new RegExp(`email: "${adminUser.email}"`, 'g');
      if (existingAdminRegex.test(authContent)) {
        this.logger.info('Admin user already exists in NextAuth configuration');
        return;
      }

      // Add the new admin user to the users array
      const newUserEntry = `  {
    id: "${adminUser.id}",
    name: "${adminUser.fullName || 'Admin User'}",
    email: "${adminUser.email}",
    password: "${hashedPassword}", // Hashed password for NextAuth
    userType: "admin",
    image: "${adminUser.image || '/Pics/GroupPic.jpg'}"
  }`;

      // Find and update the users array
      const usersArrayRegex = /const users = \[([\s\S]*?)\]/;
      const match = authContent.match(usersArrayRegex);
      
      if (match) {
        const updatedUsersArray = match[0].replace(/\]$/, `,${newUserEntry}\n]`);
        authContent = authContent.replace(usersArrayRegex, updatedUsersArray);
        
        // Write the updated content back to the file
        fs.writeFileSync(authFilePath, authContent, 'utf8');
        this.logger.success('NextAuth configuration updated successfully');
      } else {
        this.logger.warn('Could not find users array in NextAuth configuration');
      }

    } catch (error) {
      this.logger.error('Failed to update NextAuth configuration', { error: error instanceof Error ? error.message : String(error) });
      // Don't throw error as this is not critical for admin creation
    }
  }
}

// ========================================
// MAIN EXECUTION
// ========================================

async function main() {
  const logger = new Logger({ 
    dryRun: false, 
    forceUpdate: false, 
    logLevel: 'info' 
  });

  try {
    logger.info('🚀 Starting Enterprise Admin Creation Script');
    logger.info('Skillyug 2.0 - Professional Admin Setup');

    // 1. Validate environment variables
    const env = envSchema.parse({
      ADMIN_EMAIL: process.env.ADMIN_EMAIL,
      ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
      ADMIN_FULL_NAME: process.env.ADMIN_FULL_NAME,
      ADMIN_BIO: process.env.ADMIN_BIO,
      ADMIN_IMAGE_URL: process.env.ADMIN_IMAGE_URL,
      FORCE_UPDATE: process.env.FORCE_UPDATE,
      DRY_RUN: process.env.DRY_RUN,
    });

    const config: ScriptConfig = {
      dryRun: env.DRY_RUN === 'true',
      forceUpdate: env.FORCE_UPDATE === 'true',
      logLevel: 'info'
    };

    // 2. Prepare admin credentials
    const credentials: AdminCredentials = {
      email: env.ADMIN_EMAIL,
      password: env.ADMIN_PASSWORD,
      fullName: env.ADMIN_FULL_NAME || 'System Administrator',
      bio: env.ADMIN_BIO,
      imageUrl: env.ADMIN_IMAGE_URL,
    };

    logger.info('Admin Configuration', {
      email: credentials.email,
      fullName: credentials.fullName,
      forceUpdate: config.forceUpdate,
      dryRun: config.dryRun
    });

    // 3. Create admin user
    const adminCreator = new AdminCreator(prisma, logger, config);
    const result = await adminCreator.createAdmin(credentials);

    // 4. Handle result
    if (result.success) {
      logger.success('🎉 Admin creation completed successfully!');
      
      if (result.warnings && result.warnings.length > 0) {
        logger.warn('Warnings:', { warnings: result.warnings });
      }

      if (result.user) {
        logger.info('Admin User Details', {
          id: result.user.id,
          email: result.user.email,
          fullName: result.user.fullName,
          userType: result.user.userType,
          createdAt: result.user.createdAt
        });
      }

      if (config.dryRun) {
        logger.info('This was a dry run. No changes were made to the database.');
      } else {
        logger.info('The admin user can now login using NextAuth with the provided credentials.');
      }

    } else {
      logger.error('❌ Admin creation failed', { error: result.error });
      process.exit(1);
    }

  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.error('Environment validation failed', {
        errors: error.errors.map(e => `${e.path.join('.')}: ${e.message}`)
      });
    } else {
      logger.error('Script execution failed', { error: error instanceof Error ? error.message : String(error) });
    }
    process.exit(1);
  }
}

// ========================================
// GRACEFUL SHUTDOWN
// ========================================

const shutdown = async (signal: string) => {
  console.log(`\n🛑 Received ${signal}. Shutting down gracefully...`);
  await prisma.$disconnect();
  process.exit(0);
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// ========================================
// SCRIPT EXECUTION
// ========================================

main()
  .catch((error) => {
    console.error('❌ Fatal error:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });