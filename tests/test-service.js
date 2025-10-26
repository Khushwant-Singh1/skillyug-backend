const { courseService } = require('./dist/src/services/course.service');

async function testService() {
  try {
    console.log('Testing courseService.getAllCourses()...');
    
    const result = await courseService.getAllCourses(1, 10);
    
    console.log('Service method successful!');
    console.log('Number of courses:', result.courses.length);
    console.log('Pagination:', result.pagination);
    
    if (result.courses.length > 0) {
      console.log('First course from service:');
      console.log('- ID:', result.courses[0].id);
      console.log('- Name:', result.courses[0].courseName);
      console.log('- Mentor:', result.courses[0].mentor?.fullName);
    }
    
  } catch (error) {
    console.error('Error in service method:', error);
    console.error('Stack:', error.stack);
  }
}

testService();