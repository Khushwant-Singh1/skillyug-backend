// Load environment first
require('dotenv').config();

const express = require('express');
const { courseService } = require('./dist/src/services/course.service');

const app = express();
app.use(express.json());

app.get('/direct-courses', async (req, res) => {
  try {
    console.log('Direct course endpoint called');
    
    const result = await courseService.getAllCourses(1, 10);
    
    console.log('Service returned:', result.courses.length, 'courses');
    
    res.json({
      success: true,
      data: result.courses,
      pagination: result.pagination,
      debug: {
        timestamp: new Date().toISOString(),
        courseCount: result.courses.length,
        totalInDB: result.pagination.total
      }
    });
  } catch (error) {
    console.error('Error in direct endpoint:', error);
    res.status(500).json({ 
      error: error.message,
      stack: error.stack 
    });
  }
});

const server = app.listen(5002, () => {
  console.log('Direct test server running on port 5002');
  console.log('Test endpoint: GET /direct-courses');
});

// Handle cleanup properly
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing server...');
  server.close(() => {
    process.exit(0);
  });
});