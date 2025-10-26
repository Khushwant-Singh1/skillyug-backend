const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function testCourseQuery() {
  try {
    console.log('Testing direct Prisma query...');
    
    // Test 1: Simple query without includes
    console.log('\n1. Simple query:');
    const simpleCourses = await prisma.course.findMany();
    console.log('Found:', simpleCourses.length, 'courses');
    
    // Test 2: Query with mentor include only
    console.log('\n2. Query with mentor include:');
    const coursesWithMentor = await prisma.course.findMany({
      include: {
        mentor: {
          select: {
            id: true,
            fullName: true,
            email: true,
            image: true,
          },
        }
      }
    });
    console.log('Found:', coursesWithMentor.length, 'courses with mentor');
    
    // Test 3: Query with lessons include only
    console.log('\n3. Query with lessons include:');
    try {
      const coursesWithLessons = await prisma.course.findMany({
        include: {
          lessons: {
            select: {
              id: true,
              title: true,
              durationMin: true,
            },
          }
        }
      });
      console.log('Found:', coursesWithLessons.length, 'courses with lessons');
    } catch (error) {
      console.log('Error with lessons include:', error.message);
    }
    
    // Test 4: Query with _count include only
    console.log('\n4. Query with _count include:');
    try {
      const coursesWithCount = await prisma.course.findMany({
        include: {
          _count: {
            select: {
              enrollments: true,
              reviews: true,
            },
          }
        }
      });
      console.log('Found:', coursesWithCount.length, 'courses with count');
    } catch (error) {
      console.log('Error with _count include:', error.message);
    }
    
    // Test 5: Full query like repository
    console.log('\n5. Full query like repository:');
    try {
      const fullQuery = await prisma.course.findMany({
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
      });
      console.log('Found:', fullQuery.length, 'courses with full query');
      
      if (fullQuery.length > 0) {
        console.log('First course:', JSON.stringify(fullQuery[0], null, 2));
      }
    } catch (error) {
      console.log('Error with full query:', error.message);
      console.log('Full error:', error);
    }
    
  } catch (error) {
    console.error('General error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

testCourseQuery();