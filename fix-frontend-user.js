const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function fixFrontendUserPassword() {
  try {
    console.log('🔧 Fixing password for frontend user: gowejo3455@reifide.com');
    
    // Hash the password that frontend is sending
    const hashedPassword = await bcrypt.hash('1Q@zwsxedc', 12);
    
    await prisma.user.update({
      where: { email: 'gowejo3455@reifide.com' },
      data: { 
        password: hashedPassword,
        isVerified: true,
        emailVerified: new Date()
      }
    });
    
    console.log('✅ Password updated for gowejo3455@reifide.com');
    
    // Test the password
    const user = await prisma.user.findUnique({
      where: { email: 'gowejo3455@reifide.com' },
      select: { password: true, isVerified: true, email: true, fullName: true }
    });
    
    if (user?.password) {
      const isValid = await bcrypt.compare('1Q@zwsxedc', user.password);
      console.log(`Password verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
      console.log(`User verified: ${user.isVerified ? '✅ YES' : '❌ NO'}`);
      console.log(`User details:`, {
        email: user.email,
        fullName: user.fullName,
        isVerified: user.isVerified
      });
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

fixFrontendUserPassword();
