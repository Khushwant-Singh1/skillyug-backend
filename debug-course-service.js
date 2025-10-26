// Debug course service
const { CourseService } = require('./src/services/course.service');

async function testCourseService() {
  try {
    console.log('Testing CourseService...');
    
    const courseService = new CourseService();
    const result = await courseService.getAllCourses();
    
    console.log('Service result:', JSON.stringify(result, null, 2));
    
  } catch (error) {
    console.error('Service error:', error);
  }
}

testCourseService();