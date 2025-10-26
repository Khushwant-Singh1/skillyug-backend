import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { userRepository } from '../repositories/user.repository';
import { emailService } from './email.service';
import { 
  AuthenticationError,
  BusinessLogicError,
  ValidationError,
  NotFoundError,
  DuplicateError
} from '../utils/errors';
import { UserType } from '@prisma/client';
import { UserJwtPayload } from '../types/user';

/**
 * Authentication Service
 * Handles all authentication-related business logic
 */
export class AuthService {
  private readonly JWT_SECRET: string;
  private readonly JWT_EXPIRES_IN: string;
  private readonly OTP_EXPIRY_MINUTES = 10;
  private readonly RESET_TOKEN_EXPIRY_MINUTES = 10;

  constructor() {
    this.JWT_SECRET = process.env.JWT_SECRET || '';
    this.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '90d';
    
    if (!this.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is required');
    }
  }

  /**
   * Generate 6-digit OTP
   */
  private generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * Hash password
   */
  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  /**
   * Compare password
   */
  private async comparePassword(password: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  /**
   * Generate JWT token
   */
  private generateJwtToken(payload: UserJwtPayload): string {
    return jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.JWT_EXPIRES_IN,
    } as jwt.SignOptions);
  }

  /**
   * Verify JWT token
   */
  verifyJwtToken(token: string): UserJwtPayload {
    try {
      const decoded = jwt.verify(token, this.JWT_SECRET);
      if (typeof decoded === 'string') {
        throw new AuthenticationError('Invalid token format');
      }
      return decoded as UserJwtPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError('Token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError('Invalid token');
      }
      throw error;
    }
  }

  /**
   * Register new user
   */
  async register(userData: {
    fullName: string;
    email: string;
    password: string;
    userType: UserType;
  }) {
    // Check if user already exists
    const existingUser = await userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new DuplicateError('User', 'email');
    }

    // Hash password and generate OTP
    const hashedPassword = await this.hashPassword(userData.password);
    const otp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const otpExpires = new Date(Date.now() + this.OTP_EXPIRY_MINUTES * 60 * 1000);

    // Debug: Log OTP in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`🔐 Generated OTP for ${userData.email}: ${otp}`);
    }

    // Create user
    const user = await userRepository.create({
      fullName: userData.fullName,
      email: userData.email,
      password: hashedPassword,
      userType: userData.userType,
      otp: hashedOtp,
      otpExpires,
      isVerified: false,
    });

    // Send OTP email
    try {
      await emailService.sendOtpEmail(userData.email, otp);
    } catch (emailError) {
      console.error('Failed to send OTP email:', emailError);
      throw new BusinessLogicError('Failed to send verification email. Please try again later.');
    }

    return {
      user,
      message: 'Registration successful. Please check your email for verification code.'
    };
  }

  /**
   * Verify OTP
   */
  async verifyOtp(email: string, otp: string) {
    const user = await userRepository.findByEmail(email);
    if (!user) {
      throw new NotFoundError('User');
    }

    if (user.isVerified) {
      return { message: 'Email is already verified.' };
    }

    if (!user.otp || !user.otpExpires || new Date() > user.otpExpires) {
      throw new BusinessLogicError('OTP is invalid or has expired. Please request a new one.');
    }

    const isOtpValid = await bcrypt.compare(otp, user.otp);
    if (!isOtpValid) {
      throw new ValidationError('Incorrect OTP');
    }

    // Verify user email
    await userRepository.verifyEmail(email);

    return { message: 'Email verified successfully!' };
  }

  /**
   * Resend OTP
   */
  async resendOtp(email: string) {
    const user = await userRepository.findByEmail(email);
    if (!user) {
      throw new NotFoundError('User');
    }

    if (user.isVerified) {
      return { message: 'Email is already verified.' };
    }

    // Generate new OTP
    const otp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const otpExpires = new Date(Date.now() + this.OTP_EXPIRY_MINUTES * 60 * 1000);

    // Debug: Log OTP in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`🔐 Generated OTP for ${email}: ${otp}`);
    }

    // Update user with new OTP
    await userRepository.setOtp(email, hashedOtp, otpExpires);

    // Send OTP email
    try {
      await emailService.sendOtpEmail(email, otp);
    } catch (emailError) {
      console.error('Failed to send OTP email:', emailError);
      throw new BusinessLogicError('Failed to send verification email. Please try again later.');
    }

    return { message: 'New OTP sent to your email.' };
  }

  /**
   * Login user
   */
  async login(email: string, password: string) {
    const user = await userRepository.findByEmailWithPassword(email);
    if (!user || !user.password) {
      throw new AuthenticationError('Invalid email or password');
    }

    // Check if email is verified
    if (!user.isVerified) {
      throw new AuthenticationError('Please verify your email before logging in.');
    }

    // Verify password
    const isPasswordValid = await this.comparePassword(password, user.password);
    if (!isPasswordValid) {
      throw new AuthenticationError('Invalid email or password');
    }

    // Generate JWT token
    const payload: UserJwtPayload = {
      id: user.id,
      email: user.email || '',
      userType: user.userType
    };

    const token = this.generateJwtToken(payload);

    // Return user data without sensitive information
    const { password: _, otp, passwordResetToken, passwordResetExpires, ...safeUser } = user;

    return {
      token,
      user: safeUser,
      message: 'Login successful'
    };
  }

  /**
   * Check login credentials and handle unverified users
   * This method validates credentials and either logs in verified users
   * or sends OTP to unverified users
   */
  async checkLoginCredentials(email: string, password: string) {
    const user = await userRepository.findByEmailWithPassword(email);
    if (!user || !user.password) {
      throw new AuthenticationError('Invalid email or password');
    }

    // Verify password first
    const isPasswordValid = await this.comparePassword(password, user.password);
    if (!isPasswordValid) {
      throw new AuthenticationError('Invalid email or password');
    }

    // If user is verified, proceed with normal login
    if (user.isVerified) {
      const payload: UserJwtPayload = {
        id: user.id,
        email: user.email || '',
        userType: user.userType
      };

      const token = this.generateJwtToken(payload);
      const { password: _, otp, passwordResetToken, passwordResetExpires, ...safeUser } = user;

      return {
        verified: true,
        token,
        user: safeUser,
        message: 'Login successful'
      };
    }

    // User exists with correct password but is not verified
    // Generate and send new OTP
    const otp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const otpExpires = new Date(Date.now() + this.OTP_EXPIRY_MINUTES * 60 * 1000);

    // Debug: Log OTP in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`🔐 Generated OTP for unverified login ${email}: ${otp}`);
    }

    // Update user with new OTP using transaction to prevent race conditions
    await userRepository.setOtp(email, hashedOtp, otpExpires);

    // Send OTP email
    try {
      await emailService.sendOtpEmail(email, otp);
    } catch (emailError) {
      console.error('Failed to send OTP email during login:', emailError);
      throw new BusinessLogicError('Failed to send verification email. Please try again later.');
    }

    return {
      needsVerification: true,
      email: user.email,
      message: 'Your account is not verified. A new verification code has been sent to your email.',
      expiresIn: this.OTP_EXPIRY_MINUTES * 60 // in seconds
    };
  }

  /**
   * Forgot password
   */
  async forgotPassword(email: string) {
    const user = await userRepository.findByEmail(email);
    if (!user) {
      // Don't reveal if user exists or not for security
      return { message: 'If an account with that email exists, a reset link has been sent.' };
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    const resetTokenExpires = new Date(Date.now() + this.RESET_TOKEN_EXPIRY_MINUTES * 60 * 1000);

    // Save reset token
    await userRepository.setPasswordResetToken(email, hashedResetToken, resetTokenExpires);

    // Send reset email
    try {
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
      await emailService.sendPasswordResetEmail(email, resetUrl);
    } catch (emailError) {
      console.error('Failed to send reset email:', emailError);
      throw new BusinessLogicError('Failed to send reset email. Please try again later.');
    }

    return { message: 'Password reset link sent to your email.' };
  }

  /**
   * Reset password
   */
  async resetPassword(token: string, password: string, confirmPassword: string) {
    if (password !== confirmPassword) {
      throw new ValidationError('Passwords do not match');
    }

    // Hash the token to match with database
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await userRepository.findByPasswordResetToken(hashedToken);
    if (!user) {
      throw new BusinessLogicError('Reset token is invalid or has expired');
    }

    // Hash new password and update user
    const hashedPassword = await this.hashPassword(password);
    await userRepository.updatePassword(user.id, hashedPassword);

    return { message: 'Password reset successfully!' };
  }

  /**
   * Change password (for authenticated users)
   */
  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    const _user = await userRepository.findByEmailWithPassword('');
    const userById = await userRepository.findById(userId);
    
    if (!userById) {
      throw new NotFoundError('User');
    }

    const userWithPassword = await userRepository.findByEmailWithPassword(userById.email!);
    if (!userWithPassword || !userWithPassword.password) {
      throw new NotFoundError('User');
    }

    // Verify current password
    const isCurrentPasswordValid = await this.comparePassword(currentPassword, userWithPassword.password);
    if (!isCurrentPasswordValid) {
      throw new AuthenticationError('Current password is incorrect');
    }

    // Hash new password and update
    const hashedNewPassword = await this.hashPassword(newPassword);
    await userRepository.updatePassword(userId, hashedNewPassword);

    // Send confirmation email
    try {
      await emailService.sendPasswordChangeConfirmation(userById.email!);
    } catch (emailError) {
      console.error('Failed to send password change confirmation:', emailError);
      // Don't fail the request if email fails
    }

    return { message: 'Password updated successfully!' };
  }

  /**
   * Get current user
   */
  async getCurrentUser(userId: string) {
    const user = await userRepository.getProfile(userId);
    if (!user) {
      throw new NotFoundError('User');
    }
    return user;
  }

  /**
   * Refresh token (if implementing refresh token strategy)
   */
  async refreshToken(_refreshToken: string) {
    // Implement refresh token logic if needed
    // This is a placeholder for future implementation
    throw new BusinessLogicError('Refresh token functionality not implemented');
  }

  /**
   * Logout user (if implementing token blacklisting)
   */
  async logout(_token: string) {
    // Implement token blacklisting if needed
    // This is a placeholder for future implementation
    return { message: 'Logged out successfully' };
  }
}

// Export singleton instance
export const authService = new AuthService();
