import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { ResponseUtil } from '../utils/response';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { 
  registerSchema as _registerSchema,
  loginSchema as _loginSchema,
  emailLoginSchema as _emailLoginSchema,
  verifyOtpSchema as _verifyOtpSchema,
  resendOtpSchema as _resendOtpSchema,
  forgotPasswordSchema as _forgotPasswordSchema,
  resetPasswordSchema as _resetPasswordSchema,
  changePasswordSchema as _changePasswordSchema
} from '../validators/schemas';
import type {
  RegisterInput,
  LoginInput,
  EmailLoginInput,
  VerifyOtpInput,
  ResendOtpInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  ChangePasswordInput
} from '../validators/schemas';

/**
 * Authentication Controller
 * Handles HTTP requests for authentication operations
 * Business logic is delegated to AuthService
 */
export class AuthController {

  /**
   * Register new user
   * POST /api/auth/register
   */
  async register(req: Request, res: Response, next: NextFunction) {
    try {
      const userData: RegisterInput = req.body;
      
      const result = await authService.register(userData);
      
      ResponseUtil.created(res, result, 'Registration successful. Please check your email for verification.');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify OTP
   * POST /api/auth/verify-otp
   */
  async verifyOtp(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, otp }: VerifyOtpInput = req.body;
      
      const result = await authService.verifyOtp(email, otp);
      
      ResponseUtil.success(res, result, 'Email verified successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resend OTP
   * POST /api/auth/resend-otp
   */
  async resendOtp(req: Request, res: Response, next: NextFunction) {
    try {
      const { email }: ResendOtpInput = req.body;
      
      const result = await authService.resendOtp(email);
      
      ResponseUtil.success(res, result, 'New OTP sent successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Login user
   * POST /api/auth/login
   */
  async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password }: LoginInput = req.body;
      
      const result = await authService.login(email, password);
      
      ResponseUtil.success(res, result, 'Login successful');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Check login credentials (handles both verified and unverified users)
   * POST /api/auth/login-check
   */
  async checkLoginCredentials(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password }: EmailLoginInput = req.body;
      
      const result = await authService.checkLoginCredentials(email, password);
      
      if (result.needsVerification) {
        ResponseUtil.success(res, result, result.message);
      } else {
        ResponseUtil.success(res, result, result.message);
      }
    } catch (error) {
      next(error);
    }
  }

  /**
   * Forgot password
   * POST /api/auth/forgot-password
   */
  async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email }: ForgotPasswordInput = req.body;
      
      const result = await authService.forgotPassword(email);
      
      ResponseUtil.success(res, result, 'Password reset link sent');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reset password
   * PATCH /api/auth/reset-password/:token
   */
  async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.params;
      const { password, confirmPassword }: ResetPasswordInput = req.body;
      
      const result = await authService.resetPassword(token, password, confirmPassword);
      
      ResponseUtil.success(res, result, 'Password reset successful');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Change password (authenticated users)
   * PATCH /api/auth/change-password
   */
  async changePassword(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { currentPassword, newPassword }: ChangePasswordInput = req.body;
      const userId = req.user?.id;

      if (!userId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }
      
      const result = await authService.changePassword(userId, currentPassword, newPassword);
      
      ResponseUtil.success(res, result, 'Password changed successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get current user
   * GET /api/auth/me
   */
  async getCurrentUser(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.user?.id;

      if (!userId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }
      
      const user = await authService.getCurrentUser(userId);
      
      ResponseUtil.success(res, { user }, 'User profile retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Logout user
   * POST /api/auth/logout
   */
  async logout(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (token) {
        await authService.logout(token);
      }
      
      ResponseUtil.successMessage(res, 'Logged out successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Refresh token
   * POST /api/auth/refresh
   */
  async refreshToken(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.body;
      
      if (!refreshToken) {
        return ResponseUtil.fail(res, 'Refresh token is required');
      }
      
      const result = await authService.refreshToken(refreshToken);
      
      ResponseUtil.success(res, result, 'Token refreshed successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export singleton instance
export const authController = new AuthController();
