import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { ResponseUtil } from '../utils/response';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
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

// Authentication Controller - Handles HTTP requests, delegates logic to AuthService
export class AuthController {

  // Register new user
  async register(req: Request, res: Response, next: NextFunction) {
    try {
      const result = await authService.register(req.body as RegisterInput);
      ResponseUtil.created(res, result, 'Registration successful. Check your email.');
    } catch (error) {
      next(error);
    }
  }

  // Verify OTP
  async verifyOtp(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, otp } = req.body as VerifyOtpInput;
      const result = await authService.verifyOtp(email, otp);
      ResponseUtil.success(res, result, 'Email verified');
    } catch (error) {
      next(error);
    }
  }

  // Resend OTP
  async resendOtp(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body as ResendOtpInput;
      const result = await authService.resendOtp(email);
      ResponseUtil.success(res, result, 'New OTP sent');
    } catch (error) {
      next(error);
    }
  }

  // Login user
  async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body as LoginInput;
      const result = await authService.login(email, password);
      ResponseUtil.success(res, result, 'Login successful');
    } catch (error) {
      next(error);
    }
  }

  // Check login credentials (handles verified and unverified users)
  async checkLoginCredentials(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body as EmailLoginInput;
      const result = await authService.checkLoginCredentials(email, password);
      ResponseUtil.success(res, result, result.message);
    } catch (error) {
      next(error);
    }
  }

  // Forgot password
  async forgotPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { email } = req.body as ForgotPasswordInput;
      const result = await authService.forgotPassword(email);
      ResponseUtil.success(res, result, 'Password reset link sent');
    } catch (error) {
      next(error);
    }
  }

  // Reset password
  async resetPassword(req: Request, res: Response, next: NextFunction) {
    try {
      const { token } = req.params;
      const { password, confirmPassword } = req.body as ResetPasswordInput;
      const result = await authService.resetPassword(token, password, confirmPassword);
      ResponseUtil.success(res, result, 'Password reset successful');
    } catch (error) {
      next(error);
    }
  }

  // Change password
  async changePassword(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { currentPassword, newPassword } = req.body as ChangePasswordInput;
      if (!req.user?.id) {
        return ResponseUtil.unauthorized(res, 'Not authenticated');
      }
      const result = await authService.changePassword(req.user.id, currentPassword, newPassword);
      ResponseUtil.success(res, result, 'Password changed');
    } catch (error) {
      next(error);
    }
  }

  // Get current user
  async getCurrentUser(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      if (!req.user?.id) {
        return ResponseUtil.unauthorized(res, 'Not authenticated');
      }
      const user = await authService.getCurrentUser(req.user.id);
      ResponseUtil.success(res, { user }, 'User profile retrieved');
    } catch (error) {
      next(error);
    }
  }

  // Logout user
  async logout(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (token) await authService.logout(token);
      ResponseUtil.successMessage(res, 'Logged out');
    } catch (error) {
      next(error);
    }
  }

  // Refresh token
  async refreshToken(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return ResponseUtil.fail(res, 'Refresh token required');
      }
      const result = await authService.refreshToken(refreshToken);
      ResponseUtil.success(res, result, 'Token refreshed');
    } catch (error) {
      next(error);
    }
  }
}

export const authController = new AuthController();
