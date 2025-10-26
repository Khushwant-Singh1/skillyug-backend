// Debug script to test CORS configuration
const express = require('express');
const cors = require('cors');

console.log('Testing CORS configuration...');

require('dotenv').config();

try {
  const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://skillyug.com',
    'https://www.skillyug.com',
    process.env.FRONTEND_URL,
    process.env.NEXT_PUBLIC_FRONTEND_URL,
  ].filter(Boolean);

  console.log('allowedOrigins:', allowedOrigins);

  const corsOptions = {
    origin: function (origin, callback) {
      console.log('CORS origin check for:', origin);
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`CORS blocked origin: ${origin}`);
        callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
    maxAge: 86400,
  };

  console.log('CORS options created successfully');

  const app = express();
  console.log('Testing CORS middleware application...');
  app.use(cors(corsOptions));
  console.log('✅ CORS middleware applied successfully');

} catch (error) {
  console.log('❌ CORS configuration failed:', error.message);
  console.log('Error stack:', error.stack);
}
