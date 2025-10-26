const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function checkCourses() {
  try {
    console.log('Checking courses in database...');
    
    const courses = await prisma.course.findMany({
      include: {
        mentor: { 
          select: { 
            id: true, 
            fullName: true, 
            email: true 
          } 
        }
      }
    });
    
    console.log('Total courses found:', courses.length);
    
    if (courses.length > 0) {
      console.log('Courses:');
      courses.forEach((course, index) => {
        console.log(`\n${index + 1}. ${course.courseName}`);
        console.log(`   ID: ${course.id}`);
        console.log(`   Mentor: ${course.mentor?.fullName || 'No mentor'}`);
        console.log(`   Category: ${course.category}`);
        console.log(`   Active: ${course.isActive}`);
        console.log(`   Created: ${course.createdAt}`);
      });
    } else {
      console.log('No courses found in database');
    }
    
  } catch (error) {
    console.error('Error checking courses:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkCourses();