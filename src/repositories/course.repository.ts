import { Prisma, Course, Category, Difficulty } from '@prisma/client';
import prisma from '../utils/prisma';
import { DatabaseError, NotFoundError } from '../utils/errors';

/**
 * Course Repository - Handles all database operations for courses
 */
export class CourseRepository {
  /**
   * Find all courses with pagination and filtering
   */
  async findMany(
    page: number = 1,
    limit: number = 10,
    filters?: {
      category?: Category;
      difficulty?: Difficulty;
      featured?: boolean;
      search?: string;
    }
  ): Promise<{ courses: Course[]; total: number }> {
    try {
      const skip = (page - 1) * limit;
      const where: Prisma.CourseWhereInput = {};

      // Apply filters
      if (filters?.category) {
        where.category = filters.category;
      }
      
      if (filters?.difficulty) {
        where.difficulty = filters.difficulty;
      }
      
      if (typeof filters?.featured === 'boolean') {
        where.isFeatured = filters.featured;
      }
      
      if (filters?.search) {
        where.OR = [
          { courseName: { contains: filters.search, mode: 'insensitive' } },
          { description: { contains: filters.search, mode: 'insensitive' } },
        ];
      }

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

      return { courses, total };
    } catch (error) {
      throw new DatabaseError('Failed to fetch courses', error);
    }
  }

  /**
   * Find course by ID
   */
  async findById(id: string): Promise<Course | null> {
    try {
      return await prisma.course.findUnique({
        where: { id },
        include: {
          mentor: {
            select: {
              id: true,
              fullName: true,
              email: true,
              image: true,
              bio: true,
            },
          },
          lessons: {
            orderBy: { order: 'asc' },
          },
          reviews: {
            include: {
              user: {
                select: {
                  id: true,
                  fullName: true,
                  image: true,
                },
              },
            },
            orderBy: { createdAt: 'desc' },
          },
          _count: {
            select: {
              enrollments: true,
              reviews: true,
            },
          },
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to find course', error);
    }
  }

  /**
   * Find course by ID or throw error
   */
  async findByIdOrThrow(id: string): Promise<Course> {
    const course = await this.findById(id);
    if (!course) {
      throw new NotFoundError('Course');
    }
    return course;
  }

  /**
   * Find course by token (remove this method as token doesn't exist in schema)
   */
  // async findByToken(token: string): Promise<Course | null> {
  //   // Token field doesn't exist in the current schema
  //   throw new Error('Token field not available in current schema');
  // }

  /**
   * Create new course
   */
  async create(courseData: Prisma.CourseCreateInput): Promise<Course> {
    try {
      return await prisma.course.create({
        data: courseData,
        include: {
          mentor: {
            select: {
              id: true,
              fullName: true,
              email: true,
            },
          },
        },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new DatabaseError('Course with this token already exists');
        }
      }
      throw new DatabaseError('Failed to create course', error);
    }
  }

  /**
   * Update course by ID
   */
  async updateById(id: string, data: Prisma.CourseUpdateInput): Promise<Course> {
    try {
      return await prisma.course.update({
        where: { id },
        data,
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new NotFoundError('Course');
        }
      }
      throw new DatabaseError('Failed to update course', error);
    }
  }

  /**
   * Delete course by ID
   */
  async deleteById(id: string): Promise<Course> {
    try {
      return await prisma.course.delete({
        where: { id },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new NotFoundError('Course');
        }
      }
      throw new DatabaseError('Failed to delete course', error);
    }
  }

  /**
   * Check if course exists by token (remove this method as token doesn't exist)
   */
  // async existsByToken(token: string): Promise<boolean> {
  //   // Token field doesn't exist in the current schema
  //   throw new Error('Token field not available in current schema');
  // }

  /**
   * Get courses by mentor ID
   */
  async findByMentorId(mentorId: string): Promise<Course[]> {
    try {
      return await prisma.course.findMany({
        where: { mentorId },
        include: {
          _count: {
            select: {
              enrollments: true,
              reviews: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });
    } catch (error) {
      throw new DatabaseError('Failed to fetch mentor courses', error);
    }
  }

  /**
   * Get featured courses
   */
  async findFeatured(limit: number = 6): Promise<Course[]> {
    try {
      return await prisma.course.findMany({
        where: { isFeatured: true },
        take: limit,
        include: {
          mentor: {
            select: {
              id: true,
              fullName: true,
              image: true,
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
    } catch (error) {
      throw new DatabaseError('Failed to fetch featured courses', error);
    }
  }

  /**
   * Get popular courses (by enrollment count)
   */
  async findPopular(limit: number = 6): Promise<Course[]> {
    try {
      return await prisma.course.findMany({
        take: limit,
        include: {
          mentor: {
            select: {
              id: true,
              fullName: true,
              image: true,
            },
          },
          _count: {
            select: {
              enrollments: true,
              reviews: true,
            },
          },
        },
        orderBy: {
          enrollments: {
            _count: 'desc',
          },
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to fetch popular courses', error);
    }
  }

  /**
   * Search courses
   */
  async search(
    query: string,
    page: number = 1,
    limit: number = 10
  ): Promise<{ courses: Course[]; total: number }> {
    try {
      const skip = (page - 1) * limit;
      const where: Prisma.CourseWhereInput = {
        OR: [
          { courseName: { contains: query, mode: 'insensitive' } },
          { description: { contains: query, mode: 'insensitive' } },
          { category: { equals: query as Category } },
        ],
      };

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
                image: true,
              },
            },
            _count: {
              select: {
                enrollments: true,
                reviews: true,
              },
            },
          },
        }),
        prisma.course.count({ where }),
      ]);

      return { courses, total };
    } catch (error) {
      throw new DatabaseError('Failed to search courses', error);
    }
  }

  /**
   * Get course categories with count
   */
  async getCategoriesWithCount(): Promise<Array<{ category: Category; count: number }>> {
    try {
      const result = await prisma.course.groupBy({
        by: ['category'],
        _count: {
          id: true,
        },
        orderBy: {
          _count: {
            id: 'desc',
          },
        },
      });

      return result.map((item) => ({
        category: item.category,
        count: item._count.id,
      }));
    } catch (error) {
      throw new DatabaseError('Failed to get categories with count', error);
    }
  }

  /**
   * Update course statistics (for analytics) - simplified version
   */
  async updateStatistics(id: string, rating?: number): Promise<Course> {
    try {
      return await prisma.course.update({
        where: { id },
        data: {
          ...(rating && { ratingAverage: rating })
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to update course statistics', error);
    }
  }
}

// Export singleton instance
export const courseRepository = new CourseRepository();
