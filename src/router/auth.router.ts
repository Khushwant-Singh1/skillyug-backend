import { Router } from 'express';
import { authController } from '../controllers/auth.controller';
import { protect } from '../middleware/auth.middleware';
import { validateRequest } from '../middleware/validation.middleware';
import { authRateLimit, loginRateLimit, otpRateLimit, passwordResetRateLimit } from '../middleware/rateLimiter.middleware';
import { registerSchema, loginSchema, emailLoginSchema, verifyOtpSchema, resendOtpSchema, forgotPasswordSchema, resetPasswordSchema, changePasswordSchema } from '../validators/schemas';

const authRouter = Router();

// Public routes
authRouter.post('/register', otpRateLimit, validateRequest({ body: registerSchema }), (req, res, next) => authController.register(req, res, next));
authRouter.post('/verify-otp', authRateLimit, validateRequest({ body: verifyOtpSchema }), (req, res, next) => authController.verifyOtp(req, res, next));
authRouter.post('/resend-otp', otpRateLimit, validateRequest({ body: resendOtpSchema }), (req, res, next) => authController.resendOtp(req, res, next));
authRouter.post('/login', loginRateLimit, validateRequest({ body: loginSchema }), (req, res, next) => authController.login(req, res, next));
authRouter.post('/login-check', loginRateLimit, validateRequest({ body: emailLoginSchema }), (req, res, next) => authController.checkLoginCredentials(req, res, next));
authRouter.post('/forgot-password', passwordResetRateLimit, validateRequest({ body: forgotPasswordSchema }), (req, res, next) => authController.forgotPassword(req, res, next));
authRouter.patch('/reset-password/:token', authRateLimit, validateRequest({ body: resetPasswordSchema }), (req, res, next) => authController.resetPassword(req, res, next));

// Protected routes
authRouter.use(protect);
authRouter.get('/me', (req, res, next) => authController.getCurrentUser(req, res, next));
authRouter.patch('/change-password', validateRequest({ body: changePasswordSchema }), (req, res, next) => authController.changePassword(req, res, next));
authRouter.post('/logout', (req, res, next) => authController.logout(req, res, next));
authRouter.post('/refresh', (req, res, next) => authController.refreshToken(req, res, next));

export default authRouter;
