import Razorpay from "razorpay";
import dotenv from "dotenv";

dotenv.config();

// Check if we're in test mode or if Razorpay credentials are not properly configured
const isTestMode = !process.env.RAZORPAY_KEY || 
                  !process.env.RAZORPAY_SECRET || 
                  process.env.RAZORPAY_KEY === 'your_razorpay_key_here' ||
                  process.env.RAZORPAY_SECRET === 'your_razorpay_secret_here';

export const instance = isTestMode ? 
  // Mock Razorpay instance for testing
  {
    orders: {
      create: async (options: { amount: number; currency: string; [key: string]: unknown }) => {
        console.log("Mock Razorpay: Creating order", options);
        return {
          id: "mock_order_" + Date.now(),
          amount: options.amount,
          currency: options.currency,
          status: "created"
        };
      }
    },
    payments: {
      fetch: async (paymentId: string) => {
        console.log("Mock Razorpay: Fetching payment", paymentId);
        return {
          id: paymentId,
          status: "captured",
          amount: 10000
        };
      }
    }
  } :
  // Real Razorpay instance for production
  new Razorpay({
    key_id: process.env.RAZORPAY_KEY,
    key_secret: process.env.RAZORPAY_SECRET
  });
