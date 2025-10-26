import { Router } from 'express';
import { paymentController } from '../controllers/payment.controller';
import { protect, restrictTo } from '../middleware/auth.middleware';

export const paymentRouter = Router();

// Public routes
paymentRouter.get('/config', paymentController.getPaymentConfig.bind(paymentController));

// Protected routes (require authentication)
paymentRouter.use(protect);

// User payment routes
paymentRouter.post('/create-order', paymentController.createCheckoutOrder.bind(paymentController));
paymentRouter.post('/verify', paymentController.verifyPayment.bind(paymentController));
paymentRouter.post('/process-success', paymentController.processSuccessfulPayment.bind(paymentController));
paymentRouter.post('/handle-failure', paymentController.handlePaymentFailure.bind(paymentController));
paymentRouter.get('/:paymentId/status', paymentController.getPaymentStatus.bind(paymentController));

// Admin only routes
paymentRouter.post(
  '/:paymentId/refund',
  restrictTo('ADMIN'),
  paymentController.refundPayment.bind(paymentController)
);

paymentRouter.get(
  '/analytics',
  restrictTo('ADMIN'),
  paymentController.getPaymentAnalytics.bind(paymentController)
);

export default paymentRouter;
