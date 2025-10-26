// Debug script to test routers individually
const express = require('express');

console.log('Testing routers individually...');

try {
  console.log('Testing auth router...');
  const authRouter = require('./dist/src/router/auth.router.js');
  console.log('✅ Auth router loaded successfully');
} catch (error) {
  console.log('❌ Auth router failed:', error.message);
}

try {
  console.log('Testing course router...');
  const courseRouter = require('./dist/src/router/course.router.js');
  console.log('✅ Course router loaded successfully');
} catch (error) {
  console.log('❌ Course router failed:', error.message);
}

try {
  console.log('Testing payment router...');
  const paymentRouter = require('./dist/src/router/payment.router.js');
  console.log('✅ Payment router loaded successfully');
} catch (error) {
  console.log('❌ Payment router failed:', error.message);
}

try {
  console.log('Testing purchase router...');
  const purchaseRouter = require('./dist/src/router/purchase.router.js');
  console.log('✅ Purchase router loaded successfully');
} catch (error) {
  console.log('❌ Purchase router failed:', error.message);
}

try {
  console.log('Testing user router...');
  const userRouter = require('./dist/src/router/userRouter.js');
  console.log('✅ User router loaded successfully');
} catch (error) {
  console.log('❌ User router failed:', error.message);
}

console.log('Router testing complete.');
