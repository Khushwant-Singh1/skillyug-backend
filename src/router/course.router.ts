import { Router } from 'express';
import { courseController } from '../controllers/course.controller';
import { protect, restrictTo } from '../middleware/auth.middleware';
import { validateRequest } from '../middleware/validation.middleware';
import { 
  createCourseSchema,
  updateCourseSchema,
  paginationSchema as _paginationSchema
} from '../validators/schemas';

export const courseRouter = Router();

// Public routes
courseRouter.get('/', courseController.getAllCourses.bind(courseController));
courseRouter.get('/featured', courseController.getFeaturedCourses.bind(courseController));
courseRouter.get('/popular', courseController.getPopularCourses.bind(courseController));
courseRouter.get('/categories', courseController.getCategories.bind(courseController));
courseRouter.get('/search', courseController.searchCourses.bind(courseController));
courseRouter.get('/mentor/:mentorId', courseController.getCoursesByMentor.bind(courseController));
courseRouter.get('/:id', courseController.getCourseById.bind(courseController));

// Protected routes (require authentication)
courseRouter.use(protect);

// User routes
courseRouter.get('/:id/validate-access', courseController.validateCourseAccess.bind(courseController));

// Mentor and Admin routes
courseRouter.post(
  '/',
  restrictTo('MENTOR', 'ADMIN'),
  validateRequest({ body: createCourseSchema }),
  courseController.createCourse.bind(courseController)
);

courseRouter.patch(
  '/:id',
  restrictTo('MENTOR', 'ADMIN'),
  validateRequest({ body: updateCourseSchema }),
  courseController.updateCourse.bind(courseController)
);

courseRouter.delete(
  '/:id',
  restrictTo('MENTOR', 'ADMIN'),
  courseController.deleteCourse.bind(courseController)
);

courseRouter.get(
  '/:id/analytics',
  restrictTo('MENTOR', 'ADMIN'),
  courseController.getCourseAnalytics.bind(courseController)
);

// Admin only routes
courseRouter.patch(
  '/:id/featured',
  restrictTo('ADMIN'),
  courseController.toggleFeatured.bind(courseController)
);

export default courseRouter;
