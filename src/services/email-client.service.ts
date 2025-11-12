import axios from 'axios';
import { ExternalServiceError } from '../utils/errors';

/**
 * Email service that calls the frontend email API
 * This replaces the old email service that used nodemailer directly in the backend
 */
export class EmailService {
  private readonly frontendUrl: string;
  private readonly emailApiUrl: string;

  constructor() {
    this.frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    this.emailApiUrl = `${this.frontendUrl}/api/send-email`;
  }

  /**
   * Send email via frontend API
   */
  private async sendEmail(data: {
    type: string;
    email: string;
    otp?: string;
    resetUrl?: string;
    fullName?: string;
    courseName?: string;
    amount?: number;
    paymentRef?: string;
  }): Promise<void> {
    try {
      const response = await axios.post(this.emailApiUrl, data, {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 30000, // 30 second timeout
      });

      if (response.data.success) {
        console.log('✅ Email sent successfully via frontend API');
      } else {
        throw new Error('Email API returned unsuccessful response');
      }
    } catch (error) {
      console.error('❌ Failed to send email via frontend API:', error);
      if (axios.isAxiosError(error)) {
        const message = error.response?.data?.error || error.message;
        throw new ExternalServiceError('Email service', `Failed to send email: ${message}`);
      }
      throw new ExternalServiceError('Email service', 'Failed to send email');
    }
  }

  /**
   * Send OTP verification email
   */
  async sendOtpEmail(email: string, otp: string): Promise<void> {
    try {
      await this.sendEmail({
        type: 'otp',
        email,
        otp,
      });
    } catch (error) {
      console.error('Failed to send OTP email:', error);
      throw new ExternalServiceError('Email service', 'Failed to send verification email');
    }
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(email: string, resetUrl: string): Promise<void> {
    try {
      await this.sendEmail({
        type: 'password-reset',
        email,
        resetUrl,
      });
    } catch (error) {
      console.error('Failed to send password reset email:', error);
      throw new ExternalServiceError('Email service', 'Failed to send password reset email');
    }
  }

  /**
   * Send password change confirmation email
   */
  async sendPasswordChangeConfirmation(email: string): Promise<void> {
    try {
      await this.sendEmail({
        type: 'password-change',
        email,
      });
    } catch (error) {
      console.error('Failed to send password change confirmation:', error);
      throw new ExternalServiceError('Email service', 'Failed to send confirmation email');
    }
  }

  /**
   * Send welcome email after successful registration
   */
  async sendWelcomeEmail(email: string, fullName: string): Promise<void> {
    try {
      await this.sendEmail({
        type: 'welcome',
        email,
        fullName,
      });
    } catch (error) {
      console.error('Failed to send welcome email:', error);
      // Don't throw error for welcome email as it's not critical
    }
  }

  /**
   * Send purchase confirmation email
   */
  async sendPurchaseConfirmation(
    email: string,
    courseName: string,
    amount: number,
    paymentRef: string
  ): Promise<void> {
    try {
      await this.sendEmail({
        type: 'purchase',
        email,
        courseName,
        amount,
        paymentRef,
      });
    } catch (error) {
      console.error('Failed to send purchase confirmation email:', error);
      // Don't throw error for confirmation email as purchase is already complete
    }
  }
}

// Export singleton instance
export const emailService = new EmailService();
