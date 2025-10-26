const { courseRepository } = require('./dist/src/repositories/course.repository');

async function testRepository() {
  try {
    console.log('Testing courseRepository.findMany()...');
    
    const result = await courseRepository.findMany(1, 10);
    
    console.log('Repository method successful!');
    console.log('Number of courses:', result.courses.length);
    console.log('Total count:', result.total);
    
    if (result.courses.length > 0) {
      console.log('First course from repository:');
      console.log('- ID:', result.courses[0].id);
      console.log('- Name:', result.courses[0].courseName);
      console.log('- Mentor:', result.courses[0].mentor?.fullName);
    }
    
  } catch (error) {
    console.error('Error in repository method:', error);
    console.error('Stack:', error.stack);
  }
}

testRepository();