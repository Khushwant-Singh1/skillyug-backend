import { Router } from 'express';
import { authController } from '../controllers/auth.controller';
import { protect } from '../middleware/auth.middleware';
import { validateRequest } from '../middleware/validation.middleware';
import { 
  authRateLimit,
  loginRateLimit,
  otpRateLimit,
  passwordResetRateLimit
} from '../middleware/rateLimiter.middleware';
import { 
  registerSchema,
  loginSchema,
  emailLoginSchema,
  verifyOtpSchema,
  resendOtpSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema
} from '../validators/schemas';

export const authRouter = Router();

// Register a new user with OTP
authRouter.post(
  '/register',
  otpRateLimit,
  validateRequest({ body: registerSchema }),
  authController.register.bind(authController)
);

// Verify OTP
authRouter.post(
  '/verify-otp',
  authRateLimit,
  validateRequest({ body: verifyOtpSchema }),
  authController.verifyOtp.bind(authController)
);

// Resend OTP
authRouter.post(
  '/resend-otp',
  otpRateLimit,
  validateRequest({ body: resendOtpSchema }),
  authController.resendOtp.bind(authController)
);

// Login route
authRouter.post(
  '/login',
  loginRateLimit,
  validateRequest({ body: loginSchema }),
  authController.login.bind(authController)
);

// Login check route - validates credentials and handles unverified users
authRouter.post(
  '/login-check',
  loginRateLimit,
  validateRequest({ body: emailLoginSchema }),
  authController.checkLoginCredentials.bind(authController)
);

// Forgot Password
authRouter.post(
  '/forgot-password',
  passwordResetRateLimit,
  validateRequest({ body: forgotPasswordSchema }),
  authController.forgotPassword.bind(authController)
);

// Reset Password
authRouter.patch(
  '/reset-password/:token',
  authRateLimit,
  validateRequest({ body: resetPasswordSchema }),
  authController.resetPassword.bind(authController)
);

// Protected routes (require authentication)
authRouter.use(protect);

// Get current user
authRouter.get('/me', authController.getCurrentUser.bind(authController));

// Update Password (for authenticated users)
authRouter.patch(
  '/change-password',
  validateRequest({ body: changePasswordSchema }),
  authController.changePassword.bind(authController)
);

// Logout user
authRouter.post('/logout', authController.logout.bind(authController));

// Refresh token
authRouter.post('/refresh', authController.refreshToken.bind(authController));

export default authRouter;
