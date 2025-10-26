# Prisma Schema Migration Guide for Skillyug 2.0

## 📋 Overview

This document outlines the migration from MongoDB to PostgreSQL using Prisma ORM for the Skillyug 2.0 project. The new schema provides better data integrity, relationships, and scalability.

## 🗄️ Database Schema Overview

### Core Entities

1. **User Management**
   - `UserProfile` - User information (integrates with Supabase Auth)
   - `Notification` - User notifications

2. **Course System**
   - `Course` - Course information and metadata
   - `Lesson` - Individual lessons within courses
   - `CourseTag` - Tags for course categorization

3. **Learning Progress**
   - `Enrollment` - User course enrollments
   - `LessonProgress` - Individual lesson completion tracking

4. **Payment System**
   - `Payment` - Razorpay payment records
   - `UserPurchase` - Course purchase records

5. **Reviews & Analytics**
   - `Review` - Course reviews and ratings
   - `Analytics` - System metrics and analytics
   - `AdminAction` - Admin activity logs

## 🚀 Setup Instructions

### 1. Database Setup

Choose one of the following database options:

#### Option A: Local Prisma Postgres (Recommended for Development)
```bash
# Start local Prisma Postgres server
npx prisma dev
```

#### Option B: Supabase (Recommended for Production)
1. Create a new Supabase project at https://supabase.com
2. Go to Settings > Database
3. Copy the connection string
4. Update `.env` file:
```env
DATABASE_URL="postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres"
```

#### Option C: Local PostgreSQL
```bash
# Install PostgreSQL
sudo pacman -S postgresql postgresql-contrib

# Initialize and start PostgreSQL
sudo -u postgres initdb -D /var/lib/postgres/data
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database
sudo -u postgres createuser --interactive
sudo -u postgres createdb skillyug

# Update .env
DATABASE_URL="postgresql://username:password@localhost:5432/skillyug"
```

### 2. Generate Prisma Client
```bash
cd Backend
npx prisma generate
```

### 3. Run Database Migration
```bash
# Create and apply migration
npx prisma migrate dev --name init

# Or reset and apply (for development)
npx prisma migrate reset
```

### 4. Seed Database (Optional)
```bash
# Create seed file
touch prisma/seed.ts

# Run seed
npx prisma db seed
```

## 📊 Data Migration from MongoDB

### 1. Export Existing Data
```javascript
// MongoDB export script (create this in Backend/scripts/export-mongo.js)
const mongoose = require('mongoose');
const fs = require('fs');

// Connect to MongoDB and export data
// See detailed script in the migration folder
```

### 2. Import to PostgreSQL
```javascript
// Prisma import script (create this in Backend/scripts/import-prisma.ts)
import { PrismaClient } from '../src/generated/prisma';

// Transform and import data
// See detailed script in the migration folder
```

## 🔧 Key Schema Features

### Enhanced User Management
- Integrates with Supabase Auth
- User types: Student, Mentor, Admin
- Email verification tracking
- Last sign-in tracking

### Advanced Course System
- Course difficulty levels
- Prerequisites tracking
- Learning paths
- Featured courses
- Multi-language support
- Lesson ordering and preview options

### Comprehensive Progress Tracking
- Enrollment status management
- Lesson-level progress tracking
- Time spent tracking
- Completion percentages

### Robust Payment System
- Complete Razorpay integration
- Payment status tracking
- Purchase history
- Refund support

### Analytics & Monitoring
- Course completion metrics
- User engagement analytics
- Revenue tracking
- Admin action logging

## 🔄 Updating Existing Controllers

### Course Controller Migration
```typescript
// Before (MongoDB)
import Course from '../model/courseModel';

// After (Prisma)
import { PrismaClient } from '../generated/prisma';
const prisma = new PrismaClient();

// Example: Get courses
const courses = await prisma.course.findMany({
  include: {
    mentor: true,
    reviews: true,
    _count: {
      select: {
        enrollments: true,
        reviews: true
      }
    }
  }
});
```

### Payment Controller Migration
```typescript
// Before (MongoDB)
import { Payment } from '../model/paymentModel';

// After (Prisma)
const payment = await prisma.payment.create({
  data: {
    razorpayOrderId,
    razorpayPaymentId,
    razorpaySignature,
    amount: parseFloat(amount),
    course: {
      connect: { id: courseId }
    }
  }
});
```

## 📋 Migration Checklist

- [ ] Choose database provider
- [ ] Update environment variables
- [ ] Generate Prisma client
- [ ] Run initial migration
- [ ] Export existing MongoDB data
- [ ] Transform and import data
- [ ] Update controller files
- [ ] Update model imports
- [ ] Test all API endpoints
- [ ] Verify data integrity
- [ ] Update frontend API calls (if needed)
- [ ] Deploy updated backend

## 🧪 Testing

### 1. Test Database Connection
```bash
npx prisma db pull
```

### 2. Test Prisma Client
```typescript
import { PrismaClient } from './src/generated/prisma';

const prisma = new PrismaClient();

async function testConnection() {
  try {
    await prisma.$connect();
    console.log('Database connected successfully!');
  } catch (error) {
    console.error('Database connection failed:', error);
  } finally {
    await prisma.$disconnect();
  }
}

testConnection();
```

### 3. Verify Data Relations
```typescript
// Test complex queries
const courseWithDetails = await prisma.course.findUnique({
  where: { id: 'course-id' },
  include: {
    mentor: true,
    lessons: {
      orderBy: { order: 'asc' }
    },
    enrollments: {
      include: {
        user: true,
        lessonProgress: true
      }
    },
    reviews: {
      include: {
        user: true
      }
    }
  }
});
```

## 🚨 Important Notes

1. **Backup**: Always backup your MongoDB data before migration
2. **Testing**: Test thoroughly in development before production migration
3. **Gradual Migration**: Consider running both databases in parallel during transition
4. **User IDs**: Ensure Supabase user IDs are properly mapped
5. **Timestamps**: Verify all timestamps are correctly migrated
6. **Relationships**: Double-check all foreign key relationships

## 📞 Support

If you encounter issues during migration:
1. Check the Prisma documentation: https://prisma.io/docs
2. Review the error logs carefully
3. Ensure all environment variables are correctly set
4. Verify database connectivity
5. Check for any schema conflicts

## 🔄 Rollback Plan

If you need to rollback to MongoDB:
1. Keep the existing MongoDB models
2. Switch the database connection in your controllers
3. Update environment variables
4. Restart the application

This migration provides a solid foundation for scaling the Skillyug platform with better data integrity, advanced features, and improved performance.
