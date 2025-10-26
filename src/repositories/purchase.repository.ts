import { Prisma, Purchase, PurchaseItem, Category, Difficulty, PaymentStatus } from '@prisma/client';
import prisma from '../utils/prisma';
import { DatabaseError, NotFoundError } from '../utils/errors';

/**
 * Purchase Repository - Handles all database operations for purchases
 */

// Type for purchase with full relations
type PurchaseWithRelations = Purchase & {
  items: (PurchaseItem & {
    course?: {
      id: string;
      courseName: string;
      imageUrl: string;
      category: Category;
      difficulty: Difficulty;
    } | null;
    bundle?: {
      id: string;
      name: string;
      imageUrl: string | null;
    } | null;
  })[];
  user?: {
    id: string;
    fullName: string | null;
    email: string | null;
  } | null;
  payments?: Array<{
    id: string;
    status: PaymentStatus;
    amount: Prisma.Decimal;
    providerPaymentId: string;
    createdAt: Date;
  }>;
};

export class PurchaseRepository {
  /**
   * Create new purchase with items
   */
  async createPurchase(
    userId: string,
    items: Array<{
      courseId?: string;
      bundleId?: string;
      purchasePrice: number;
    }>,
    totalAmount: number
  ): Promise<PurchaseWithRelations> {
    try {
      return await prisma.purchase.create({
        data: {
          userId,
          totalAmount,
          status: 'PENDING',
          items: {
            create: items,
          },
        },
        include: {
          items: {
            include: {
              course: true,
              bundle: true,
            },
          },
          user: {
            select: {
              id: true,
              fullName: true,
              email: true,
            },
          },
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to create purchase', error);
    }
  }

  /**
   * Find purchase by ID
   */
  async findById(id: string): Promise<PurchaseWithRelations | null> {
    try {
      return await prisma.purchase.findUnique({
        where: { id },
        include: {
          items: {
            include: {
              course: true,
              bundle: true,
            },
          },
          user: {
            select: {
              id: true,
              fullName: true,
              email: true,
            },
          },
          payments: true,
        },
      });
    } catch (error) {
      throw new DatabaseError('Failed to find purchase', error);
    }
  }

  /**
   * Find purchases by user ID
   */
  async findByUserId(
    userId: string,
    page: number = 1,
    limit: number = 10
  ): Promise<{ purchases: PurchaseWithRelations[]; total: number }> {
    try {
      const skip = (page - 1) * limit;

      const [purchases, total] = await Promise.all([
        prisma.purchase.findMany({
          where: { userId },
          skip,
          take: limit,
          include: {
            items: {
              include: {
                course: {
                  select: {
                    id: true,
                    courseName: true,
                    imageUrl: true,
                    category: true,
                    difficulty: true,
                  },
                },
                bundle: {
                  select: {
                    id: true,
                    name: true,
                    imageUrl: true,
                  },
                },
              },
            },
            payments: {
              select: {
                id: true,
                status: true,
                amount: true,
                providerPaymentId: true,
                createdAt: true,
              },
            },
          },
          orderBy: { purchasedAt: 'desc' },
        }),
        prisma.purchase.count({ where: { userId } }),
      ]);

      return { purchases, total };
    } catch (error) {
      throw new DatabaseError('Failed to fetch user purchases', error);
    }
  }

  /**
   * Check if user has purchased a specific course
   */
  async hasUserPurchasedCourse(userId: string, courseId: string): Promise<boolean> {
    try {
      const purchaseItem = await prisma.purchaseItem.findFirst({
        where: {
          courseId,
          purchase: {
            userId,
            status: 'COMPLETED',
          },
        },
      });

      return !!purchaseItem;
    } catch (error) {
      throw new DatabaseError('Failed to check course purchase status', error);
    }
  }

  /**
   * Update purchase status
   */
  async updateStatus(id: string, status: 'PENDING' | 'COMPLETED' | 'FAILED' | 'REFUNDED'): Promise<Purchase> {
    try {
      return await prisma.purchase.update({
        where: { id },
        data: { status },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new NotFoundError('Purchase');
        }
      }
      throw new DatabaseError('Failed to update purchase status', error);
    }
  }

  /**
   * Get purchase statistics
   */
  async getPurchaseStats(
    userId?: string,
    dateRange?: {
      startDate: Date;
      endDate: Date;
    }
  ): Promise<{
    totalPurchases: number;
    totalRevenue: number;
    averageOrderValue: number;
  }> {
    try {
      const where: Prisma.PurchaseWhereInput = {
        status: 'COMPLETED',
      };

      if (userId) {
        where.userId = userId;
      }

      if (dateRange) {
        where.purchasedAt = {
          gte: dateRange.startDate,
          lte: dateRange.endDate,
        };
      }

      const result = await prisma.purchase.aggregate({
        where,
        _count: {
          id: true,
        },
        _sum: {
          totalAmount: true,
        },
        _avg: {
          totalAmount: true,
        },
      });

      return {
        totalPurchases: result._count.id || 0,
        totalRevenue: Number(result._sum.totalAmount) || 0,
        averageOrderValue: Number(result._avg.totalAmount) || 0,
      };
    } catch (error) {
      throw new DatabaseError('Failed to get purchase statistics', error);
    }
  }

  /**
   * Get popular courses by purchase count
   */
  async getPopularCourses(limit: number = 10): Promise<Array<{
    courseId: string;
    courseName: string;
    purchaseCount: number;
    totalRevenue: number;
  }>> {
    try {
      const result = await prisma.purchaseItem.groupBy({
        by: ['courseId'],
        where: {
          courseId: { not: null },
          purchase: {
            status: 'COMPLETED',
          },
        },
        _count: {
          id: true,
        },
        _sum: {
          purchasePrice: true,
        },
        orderBy: {
          _count: {
            id: 'desc',
          },
        },
        take: limit,
      });

      // Get course details
      const courseIds = result.map(item => item.courseId).filter(Boolean) as string[];
      const courses = await prisma.course.findMany({
        where: {
          id: { in: courseIds },
        },
        select: {
          id: true,
          courseName: true,
        },
      });

      return result.map(item => {
        const course = courses.find(c => c.id === item.courseId);
        return {
          courseId: item.courseId!,
          courseName: course?.courseName || 'Unknown Course',
          purchaseCount: item._count.id,
          totalRevenue: Number(item._sum.purchasePrice) || 0,
        };
      });
    } catch (error) {
      throw new DatabaseError('Failed to get popular courses', error);
    }
  }

  /**
   * Get revenue by time period
   */
  async getRevenueByPeriod(
    period: 'day' | 'week' | 'month',
    dateRange: {
      startDate: Date;
      endDate: Date;
    }
  ): Promise<Array<{
    period: string;
    revenue: number;
    orderCount: number;
  }>> {
    try {
      // This is a simplified implementation
      // In a real application, you might want to use more sophisticated date grouping
      const purchases = await prisma.purchase.findMany({
        where: {
          status: 'COMPLETED',
          purchasedAt: {
            gte: dateRange.startDate,
            lte: dateRange.endDate,
          },
        },
        select: {
          totalAmount: true,
          purchasedAt: true,
        },
        orderBy: {
          purchasedAt: 'asc',
        },
      });

      // Group by period (simplified grouping by day)
      const grouped = purchases.reduce((acc, purchase) => {
        const date = purchase.purchasedAt.toISOString().split('T')[0];
        if (!acc[date]) {
          acc[date] = { revenue: 0, orderCount: 0 };
        }
        acc[date].revenue += Number(purchase.totalAmount);
        acc[date].orderCount += 1;
        return acc;
      }, {} as Record<string, { revenue: number; orderCount: number }>);

      return Object.entries(grouped).map(([period, data]) => ({
        period,
        revenue: data.revenue,
        orderCount: data.orderCount,
      }));
    } catch (error) {
      throw new DatabaseError('Failed to get revenue by period', error);
    }
  }
}

// Export singleton instance
export const purchaseRepository = new PurchaseRepository();
