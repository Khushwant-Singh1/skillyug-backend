const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function fixTestUserPassword() {
  try {
    console.log('🔧 Fixing test user password...');
    
    // Hash the password with the same parameters as the auth service (12 rounds)
    const hashedPassword = await bcrypt.hash('testpassword', 12);
    
    await prisma.user.update({
      where: { email: 'test@example.com' },
      data: { 
        password: hashedPassword,
        isVerified: true,
        emailVerified: new Date()
      }
    });
    
    console.log('✅ Password updated');
    
    // Test the password
    const user = await prisma.user.findUnique({
      where: { email: 'test@example.com' },
      select: { password: true, isVerified: true }
    });
    
    if (user?.password) {
      const isValid = await bcrypt.compare('testpassword', user.password);
      console.log(`Password verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
      console.log(`User verified: ${user.isVerified ? '✅ YES' : '❌ NO'}`);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

fixTestUserPassword();
