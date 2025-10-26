// Debug script to test database and Prisma import
console.log('Testing database connection...');

try {
  console.log('1. Loading dotenv...');
  require('dotenv').config();
  console.log('✅ Environment loaded');

  console.log('2. Testing Prisma import...');
  const prisma = require('./dist/src/utils/prisma.js');
  console.log('✅ Prisma imported');

  console.log('3. Testing Razorpay import...');
  const Razorpay = require('razorpay');
  const instance = new Razorpay({
    key_id: process.env.RAZORPAY_KEY,
    key_secret: process.env.RAZORPAY_SECRET
  });
  console.log('✅ Razorpay configured');

  console.log('All database/external services loaded successfully!');

} catch (error) {
  console.log('❌ Error occurred:', error.message);
  console.log('Error stack:', error.stack);
}
