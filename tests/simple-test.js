const express = require('express');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();

app.get('/test-courses', async (req, res) => {
  try {
    console.log('Test endpoint called');
    
    // Test 1: Simple query
    const courses = await prisma.course.findMany({
      take: 1
    });
    console.log('Simple query result:', courses.length);
    
    res.json({
      success: true,
      count: courses.length,
      data: courses
    });
  } catch (error) {
    console.error('Error in test endpoint:', error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(5001, () => {
  console.log('Test server running on port 5001');
});