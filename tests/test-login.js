const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function createVerifiedTestUser() {
  try {
    const email = 'test@example.com';
    const password = 'Test123!@#';
    const hashedPassword = await bcrypt.hash(password, 12);

    // Delete existing user if exists
    await prisma.user.deleteMany({
      where: { email }
    });

    // Create verified user
    const user = await prisma.user.create({
      data: {
        fullName: 'Test User',
        email: email,
        password: hashedPassword,
        userType: 'STUDENT',
        isVerified: true,
        emailVerified: new Date()
      }
    });

    console.log('✅ Created verified test user:');
    console.log('Email:', email);
    console.log('Password:', password);
    console.log('User Type: STUDENT');
    console.log('Verified:', user.isVerified);

  } catch (error) {
    console.error('❌ Error creating test user:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createVerifiedTestUser();
