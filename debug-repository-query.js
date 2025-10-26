const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function debugRepositoryQuery() {
  try {
    console.log('Testing repository-like query...');
    
    // Simulate the exact query from repository
    const page = 1;
    const limit = 10;
    const skip = (page - 1) * limit;
    const where = {}; // No filters
    
    console.log('Query parameters:');
    console.log('- skip:', skip);
    console.log('- limit:', limit);
    console.log('- where:', where);
    
    const [courses, total] = await Promise.all([
      prisma.course.findMany({
        where,
        skip,
        take: limit,
        include: {
          mentor: {
            select: {
              id: true,
              fullName: true,
              email: true,
              image: true,
            },
          },
          lessons: {
            select: {
              id: true,
              title: true,
              durationMin: true,
            },
          },
          _count: {
            select: {
              enrollments: true,
              reviews: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.course.count({ where }),
    ]);
    
    console.log('\nRepository query results:');
    console.log('- courses.length:', courses.length);
    console.log('- total:', total);
    
    if (courses.length > 0) {
      console.log('- first course ID:', courses[0].id);
      console.log('- first course name:', courses[0].courseName);
    }
    
  } catch (error) {
    console.error('Repository query error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

debugRepositoryQuery();