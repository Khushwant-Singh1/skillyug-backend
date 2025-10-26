// Debug script to replicate the exact index.js setup with debugging
const express = require('express');
const dotenv = require('dotenv');
const Razorpay = require('razorpay');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

console.log('Replicating exact index.js setup...');

try {
  console.log('1. Loading environment variables...');
  dotenv.config();
  console.log('✅ Environment variables loaded');

  console.log('2. Database connection function...');
  const prisma = require('./dist/src/utils/prisma.js');
  async function connectToDatabase() {
    try {
      await (prisma.default || prisma).$connect();
      console.log('✅ Database connected successfully');
    } catch (error) {
      console.error('❌ Database connection failed:', error);
      throw error;
    }
  }
  console.log('✅ Database connection function defined');

  console.log('3. Razorpay instance...');
  if (!process.env.RAZORPAY_KEY || !process.env.RAZORPAY_SECRET) {
    console.error("❌ Fatal Error: Razorpay Key or Secret is not defined in .env file");
    throw new Error("Razorpay credentials missing");
  }
  const instance = new Razorpay({
    key_id: process.env.RAZORPAY_KEY,
    key_secret: process.env.RAZORPAY_SECRET
  });
  console.log('✅ Razorpay instance created');

  console.log('4. Express app initialization...');
  const app = express();
  const PORT = process.env.PORT || 5000;
  console.log('✅ Express app created');

  console.log('5. Helmet middleware...');
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

  console.log('6. CORS configuration...');
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

  console.log('7. Rate limiting...');
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

  console.log('8. Basic middleware...');
  app.use(morgan('dev'));
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true }));
  console.log('✅ Basic middleware configured');

  console.log('9. Health check routes...');
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
  console.log('✅ Health check routes added');

  console.log('10. Loading routers...');
  const authRouter = require('./dist/src/router/auth.router.js');
  const courseRouter = require('./dist/src/router/course.router.js');
  const paymentRouter = require('./dist/src/router/payment.router.js');
  const purchaseRouter = require('./dist/src/router/purchase.router.js');
  const userRouter = require('./dist/src/router/userRouter.js');
  console.log('✅ Routers loaded');

  console.log('11. Mounting API routes...');
  app.use("/api/auth", authRouter.default || authRouter);
  app.use("/api/courses", courseRouter.default || courseRouter);
  app.use("/api/payments", paymentRouter.default || paymentRouter);
  app.use("/api/purchases", purchaseRouter.default || purchaseRouter);
  app.use("/api/users", userRouter.default || userRouter);
  console.log('✅ API routes mounted');

  console.log('12. 404 handler...');
  app.all('*', (req, res, next) => {
    res.status(404).json({
      status: 'fail',
      message: `Can't find ${req.originalUrl} on this server!`
    });
  });
  console.log('✅ 404 handler added');

  console.log('13. Global error handler...');
  const { globalErrorHandler } = require('./dist/src/middleware/errorHandler.middleware.js');
  app.use(globalErrorHandler);
  console.log('✅ Global error handler added');

  console.log('14. Database connection...');
  connectToDatabase().then(() => {
    console.log('✅ Database connected');
    console.log('🎉 All setup completed successfully!');
  }).catch((error) => {
    console.log('❌ Database connection failed:', error.message);
  });

} catch (error) {
  console.log('❌ Error occurred at step:', error.message);
  console.log('Error stack:', error.stack);
}
