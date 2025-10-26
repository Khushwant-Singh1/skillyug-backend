const { PrismaClient } = require('@prisma/client');

async function testDirectQuery() {
  const prisma = new PrismaClient();
  
  try {
    console.log('Testing direct database query...');
    
    // Test the exact query from the repository
    const result = await prisma.course.findMany({
      where: {},
      skip: 0,
      take: 10,
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
    
    console.log('Query successful!');
    console.log('Number of courses:', result.length);
    
    if (result.length > 0) {
      console.log('First course:');
      console.log('- ID:', result[0].id);
      console.log('- Name:', result[0].courseName);
      console.log('- Mentor:', result[0].mentor?.fullName);
    }
    
  } catch (error) {
    console.error('Error executing query:', error);
  } finally {
    await prisma.$disconnect();
  }
}

testDirectQuery();