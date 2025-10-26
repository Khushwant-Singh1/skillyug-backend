// Debug script to test the middleware-based 404 handler
const express = require('express');

console.log('Testing middleware-based 404 handler...');

try {
  const app = express();
  
  console.log('1. Testing middleware-based 404 handler...');
  app.use((req, res, next) => {
    res.status(404).json({
      status: 'fail',
      message: `Can't find ${req.originalUrl} on this server!`
    });
  });
  console.log('✅ 404 handler applied successfully');

} catch (error) {
  console.log('❌ Error occurred:', error.message);
  console.log('Error stack:', error.stack);
}
