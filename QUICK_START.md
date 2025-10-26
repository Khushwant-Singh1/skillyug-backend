# Prisma Quick Start Guide

## 🚀 Quick Setup (5 minutes)

### 1. Generate Prisma Client
```bash
cd Backend
pnpm run db:generate
```

### 2. Start Local Database
```bash
# Start Prisma's local PostgreSQL server
npx prisma dev
```

### 3. Run Migration
```bash
pnpm run db:migrate
```

### 4. Seed Database
```bash
pnpm run db:seed
```

### 5. View Database (Optional)
```bash
pnpm run db:studio
```

## 🎯 Test the Setup

### Test Database Connection
```typescript
import prisma from './src/utils/prisma';

async function test() {
  const courses = await prisma.course.findMany();
  console.log('Courses:', courses.length);
}

test();
```

### View Sample Data
After seeding, you'll have:
- 3 users (1 mentor, 1 admin, 1 student)
- 4 courses with lessons
- 1 enrollment with progress
- 1 purchase record
- 1 review
- Analytics data

## 📋 Available Commands

```bash
# Database operations
pnpm run db:generate   # Generate Prisma client
pnpm run db:migrate    # Create and apply migration
pnpm run db:reset      # Reset database (⚠️ deletes all data)
pnpm run db:seed       # Populate with sample data
pnpm run db:studio     # Open Prisma Studio (database GUI)
pnpm run db:push       # Push schema changes without migration

# Development
pnpm run dev           # Start development server
pnpm run build         # Build TypeScript
```

## 🔧 Using in Controllers

### Example: Updated Course Controller
```typescript
import prisma from '../utils/prisma';

export const getCourses = async (req: Request, res: Response) => {
  try {
    const courses = await prisma.course.findMany({
      include: {
        mentor: {
          select: {
            id: true,
            fullName: true,
            email: true
          }
        },
        tags: true,
        _count: {
          select: {
            enrollments: true,
            reviews: true
          }
        }
      },
      orderBy: {
        featured: 'desc'
      }
    });

    res.json({
      success: true,
      count: courses.length,
      data: courses
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching courses',
      error: (error as Error).message
    });
  }
};
```

## 🛠️ Database Options

### Option 1: Local Prisma Postgres (Recommended)
- Zero configuration
- Automatic management
- Perfect for development

### Option 2: Supabase (Production Ready)
1. Create project at https://supabase.com
2. Get connection string from Settings > Database
3. Update `.env`:
```env
DATABASE_URL="postgresql://postgres:[password]@[host]:5432/postgres"
```

### Option 3: Railway/Vercel/Neon
Similar to Supabase - just update the DATABASE_URL

## 📊 Schema Highlights

### Core Features
- ✅ User profiles with Supabase integration
- ✅ Advanced course management
- ✅ Progress tracking
- ✅ Payment processing
- ✅ Reviews and ratings
- ✅ Analytics
- ✅ Admin actions logging

### Advanced Features
- Course prerequisites
- Learning paths
- Lesson ordering
- Time tracking
- Revenue analytics
- User engagement metrics

## 🔍 Troubleshooting

### Common Issues

**Cannot find module '../generated/prisma'**
```bash
pnpm run db:generate
```

**Database connection failed**
```bash
npx prisma dev  # Start local database
```

**Migration failed**
```bash
pnpm run db:reset  # Reset and start fresh
pnpm run db:migrate
```

### Reset Everything
```bash
pnpm run db:reset
pnpm run db:migrate
pnpm run db:seed
```

## 🎉 You're Ready!

Your Prisma setup is complete with:
- ✅ Modern PostgreSQL database
- ✅ Type-safe queries
- ✅ Rich relationships
- ✅ Sample data for testing
- ✅ Analytics capabilities
- ✅ Production-ready schema

Start building amazing features! 🚀
