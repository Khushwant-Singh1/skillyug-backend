const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function checkAndCreateTestUser() {
  try {
    console.log('🔍 Checking existing users...');
    
    // Check existing users
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        fullName: true,
        isVerified: true,
        userType: true,
        password: true
      }
    });
    
    console.log(`Found ${users.length} users:`);
    users.forEach(user => {
      console.log(`- ${user.email}: verified=${user.isVerified}, type=${user.userType}, hasPassword=${!!user.password}`);
    });
    
    // Check if test@example.com exists
    const testUser = await prisma.user.findUnique({
      where: { email: 'test@example.com' }
    });
    
    if (!testUser) {
      console.log('\n🔧 Creating test user: test@example.com');
      
      // Hash the password
      const hashedPassword = await bcrypt.hash('testpassword', 12);
      
      const newUser = await prisma.user.create({
        data: {
          email: 'test@example.com',
          fullName: 'Test User',
          password: hashedPassword,
          userType: 'STUDENT',
          isVerified: true, // Set to true for testing
          emailVerified: new Date() // Also set this for completeness
        }
      });
      
      console.log('✅ Test user created:', {
        id: newUser.id,
        email: newUser.email,
        fullName: newUser.fullName,
        isVerified: newUser.isVerified
      });
    } else {
      console.log('\n📋 Test user already exists');
      if (!testUser.isVerified) {
        console.log('⚠️  Test user is not verified, updating...');
        await prisma.user.update({
          where: { email: 'test@example.com' },
          data: { 
            isVerified: true,
            emailVerified: new Date()
          }
        });
        console.log('✅ Test user verified');
      }
      
      if (!testUser.password) {
        console.log('⚠️  Test user has no password, adding...');
        const hashedPassword = await bcrypt.hash('testpassword', 12);
        await prisma.user.update({
          where: { email: 'test@example.com' },
          data: { password: hashedPassword }
        });
        console.log('✅ Test user password set');
      }
    }
    
    console.log('\n🧪 Testing password verification...');
    const userWithPassword = await prisma.user.findUnique({
      where: { email: 'test@example.com' },
      select: { password: true }
    });
    
    if (userWithPassword?.password) {
      const isValid = await bcrypt.compare('testpassword', userWithPassword.password);
      console.log(`Password verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkAndCreateTestUser();
