// Debug script to test error handler middleware
console.log('Testing error handler middleware...');

try {
  console.log('1. Loading dotenv...');
  require('dotenv').config();
  console.log('✅ Environment loaded');

  console.log('2. Testing error handler import...');
  const { globalErrorHandler } = require('./dist/src/middleware/errorHandler.middleware.js');
  console.log('✅ Error handler imported');

  console.log('3. Testing error handler application...');
  const express = require('express');
  const app = express();
  
  // Add a test route that throws an error
  app.get('/test-error', (req, res, next) => {
    const error = new Error('Test error');
    next(error);
  });
  
  app.use(globalErrorHandler);
  console.log('✅ Error handler applied');

  console.log('Error handler middleware loaded successfully!');

} catch (error) {
  console.log('❌ Error occurred:', error.message);
  console.log('Error stack:', error.stack);
}
