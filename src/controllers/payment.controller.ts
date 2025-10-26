import { Response, NextFunction } from 'express';
import { paymentService } from '../services/payment.service';
import { ResponseUtil } from '../utils/response';
import { AuthenticatedRequest } from '../middleware/auth.middleware';

/**
 * Payment Controller
 * Handles HTTP requests for payment operations
 * Business logic is delegated to PaymentService
 */
export class PaymentController {

  /**
   * Create payment order for course purchase
   * POST /api/payments/create-order
   */
  async createCheckoutOrder(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { amount, courseId } = req.body;
      const userId = req.user?.id;

      if (!userId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }

      if (!amount || !courseId) {
        return ResponseUtil.fail(res, 'Amount and courseId are required');
      }
      
      const order = await paymentService.createCheckoutOrder(amount, courseId, userId);
      
      ResponseUtil.created(res, order, 'Payment order created successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify payment signature and complete purchase
   * POST /api/payments/verify
   */
  async verifyPayment(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { 
        razorpayPaymentId, 
        razorpayOrderId, 
        razorpaySignature, 
        courseId 
      } = req.body;

      if (!razorpayPaymentId || !razorpayOrderId || !razorpaySignature || !courseId) {
        return ResponseUtil.fail(res, 'Missing payment verification details');
      }
      
      const result = await paymentService.verifyPayment(
        razorpayPaymentId,
        razorpayOrderId,
        razorpaySignature,
        courseId
      );
      
      ResponseUtil.success(res, result, 'Payment verified successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Process successful payment
   * POST /api/payments/process-success
   */
  async processSuccessfulPayment(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { courseId, paymentData } = req.body;
      const userId = req.user?.id;

      if (!userId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }

      if (!courseId || !paymentData) {
        return ResponseUtil.fail(res, 'courseId and paymentData are required');
      }
      
      const result = await paymentService.processSuccessfulPayment(userId, courseId, paymentData);
      
      ResponseUtil.success(res, result, 'Payment processed successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Handle payment failure
   * POST /api/payments/handle-failure
   */
  async handlePaymentFailure(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { courseId, errorDetails } = req.body;
      const userId = req.user?.id;

      if (!userId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }

      if (!courseId) {
        return ResponseUtil.fail(res, 'courseId is required');
      }
      
      const result = await paymentService.handlePaymentFailure(userId, courseId, errorDetails);
      
      ResponseUtil.success(res, result, 'Payment failure handled');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get Razorpay configuration for frontend
   * GET /api/payments/config
   */
  async getPaymentConfig(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const config = {
        razorpayKey: paymentService.getRazorpayKey(),
        currency: 'INR'
      };
      
      ResponseUtil.success(res, config, 'Payment configuration retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get payment status
   * GET /api/payments/:paymentId/status
   */
  async getPaymentStatus(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { paymentId } = req.params;
      
      const status = await paymentService.getPaymentStatus(paymentId);
      
      ResponseUtil.success(res, { status }, 'Payment status retrieved successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Refund payment (Admin only)
   * POST /api/payments/:paymentId/refund
   */
  async refundPayment(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const { paymentId } = req.params;
      const { amount, reason } = req.body;
      const adminId = req.user?.id;

      if (!adminId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }

      if (!amount) {
        return ResponseUtil.fail(res, 'Refund amount is required');
      }
      
      const result = await paymentService.refundPayment(paymentId, amount, adminId, reason);
      
      ResponseUtil.success(res, result, 'Payment refunded successfully');
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get payment analytics (Admin only)
   * GET /api/payments/analytics
   */
  async getPaymentAnalytics(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    try {
      const adminId = req.user?.id;
      const { startDate, endDate } = req.query;

      if (!adminId) {
        return ResponseUtil.unauthorized(res, 'User not authenticated');
      }

      const dateRange = startDate && endDate ? {
        startDate: new Date(startDate as string),
        endDate: new Date(endDate as string)
      } : undefined;
      
      const analytics = await paymentService.getPaymentAnalytics(adminId, dateRange);
      
      ResponseUtil.success(res, { analytics }, 'Payment analytics retrieved successfully');
    } catch (error) {
      next(error);
    }
  }
}

// Export singleton instance
export const paymentController = new PaymentController();
