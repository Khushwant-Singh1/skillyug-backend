// Debug script to test Express app setup step by step
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

console.log('Step-by-step Express app setup...');

try {
  console.log('1. Loading environment variables...');
  dotenv.config();
  console.log('✅ Environment variables loaded');

  console.log('2. Creating Express app...');
  const app = express();
  console.log('✅ Express app created');

  console.log('3. Setting up Helmet...');
  app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }));
  console.log('✅ Helmet configured');

  console.log('4. Setting up CORS...');
  const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://skillyug.com',
    'https://www.skillyug.com',
    process.env.FRONTEND_URL,
    process.env.NEXT_PUBLIC_FRONTEND_URL,
  ].filter(Boolean);

  const corsOptions = {
    origin: function (origin, callback) {
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
  app.use(cors(corsOptions));
  console.log('✅ CORS configured');

  console.log('5. Setting up rate limiting...');
  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Too many requests from this IP, please try again after 15 minutes',
      code: 'RATE_LIMIT_EXCEEDED'
    },
    skip: (req) => {
      return req.path === '/api/test' || req.path === '/';
    }
  });

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Too many authentication attempts, please try again after 15 minutes',
      code: 'AUTH_RATE_LIMIT_EXCEEDED'
    }
  });

  app.use('/api', generalLimiter);
  app.use('/api/auth', authLimiter);
  console.log('✅ Rate limiting configured');

  console.log('6. Setting up basic middleware...');
  app.use(morgan('dev'));
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true }));
  console.log('✅ Basic middleware configured');

  console.log('7. Adding basic routes...');
  app.get('/api/test', (req, res) => {
    res.status(200).json({ 
      message: 'Backend API is working!',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  });

  app.get("/", (req, res) => {
    res.status(200).send("<h1>Backend is up and running!</h1>");
  });

  app.get('/api/getKey', (req, res) => {
    res.status(200).json({ key: process.env.RAZORPAY_KEY });
  });
  console.log('✅ Basic routes added');

  console.log('8. Loading compiled routers...');
  const authRouter = require('./dist/src/router/auth.router.js');
  const courseRouter = require('./dist/src/router/course.router.js');
  const paymentRouter = require('./dist/src/router/payment.router.js');
  const purchaseRouter = require('./dist/src/router/purchase.router.js');
  const userRouter = require('./dist/src/router/userRouter.js');
  console.log('✅ Routers loaded');

  console.log('9. Mounting routers...');
  app.use("/api/auth", authRouter.default || authRouter);
  console.log('✅ Auth router mounted');
  
  app.use("/api/courses", courseRouter.default || courseRouter);
  console.log('✅ Course router mounted');
  
  app.use("/api/payments", paymentRouter.default || paymentRouter);
  console.log('✅ Payment router mounted');
  
  app.use("/api/purchases", purchaseRouter.default || purchaseRouter);
  console.log('✅ Purchase router mounted');
  
  app.use("/api/users", userRouter.default || userRouter);
  console.log('✅ User router mounted');

  console.log('All steps completed successfully!');

} catch (error) {
  console.log('❌ Error occurred:', error.message);
  console.log('Error stack:', error.stack);
}
