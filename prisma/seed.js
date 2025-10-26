const { PrismaClient, UserType, Category, Difficulty, Prisma, PaymentStatus, EnrollmentStatus, AnalyticMetric, NotificationType } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Starting database seed...");

  // --- Course Tags ---
  const tags = await Promise.all([
    prisma.courseTag.upsert({
      where: { name: "Beginner Friendly" },
      update: {},
      create: { name: "Beginner Friendly", color: "#10B981" },
    }),
    prisma.courseTag.upsert({
      where: { name: "Popular" },
      update: {},
      create: { name: "Popular", color: "#F59E0B" },
    }),
    prisma.courseTag.upsert({
      where: { name: "Hands-on" },
      update: {},
      create: { name: "Hands-on", color: "#3B82F6" },
    }),
    prisma.courseTag.upsert({
      where: { name: "Certification" },
      update: {},
      create: { name: "Certification", color: "#8B5CF6" },
    }),
    prisma.courseTag.upsert({
      where: { name: "Project-based" },
      update: {},
      create: { name: "Project-based", color: "#EF4444" },
    }),
  ]);
  console.log("✅ Created course tags");

  // --- Mentor User ---
  const mentor = await prisma.user.upsert({
    where: { email: "mentor@skillyug.com" },
    update: {},
    create: {
      id: "mentor-uuid-1",
      email: "mentor@skillyug.com",
      fullName: "Dr. Sarah Johnson",
      userType: UserType.MENTOR,
      emailVerified: new Date(),
      isVerified: true,
      bio: "Experienced software engineer and educator with 10+ years in web development.",
    },
  });
  console.log("✅ Created mentor user");

  // --- Admin User ---
  const admin = await prisma.user.upsert({
    where: { email: "admin@skillyug.com" },
    update: {},
    create: {
      id: "admin-uuid-1",
      email: "admin@skillyug.com",
      fullName: "Admin User",
      userType: UserType.ADMIN,
      emailVerified: new Date(),
      isVerified: true,
      bio: "Platform administrator managing courses and user accounts.",
    },
  });
  console.log("✅ Created admin user");

  // --- Courses ---
  const courses = await Promise.all([
    // Python Track Courses
    prisma.course.upsert({
      where: { id: "python_beginner" },
      update: {},
      create: {
        id: "python_beginner",
        courseName: "Python Beginner",
        token: 20,
        price: new Prisma.Decimal("1299.00"),
        imageUrl: "https://images.unsplash.com/photo-1526379095098-d400fd0bf935?w=400",
        description: "Perfect for absolute beginners. Learn: Variables, loops, functions, data types. Hands-on: Mini projects (Calculator, Quiz App)",
        category: Category.PROGRAMMING,
        difficulty: Difficulty.BEGINNER,
        durationHours: 22,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.5"),
        reviewCount: 1000,
        tags: {
          connect: [{ id: tags[0].id }, { id: tags[1].id }],
        },
      },
    }),
    prisma.course.upsert({
      where: { id: "python_bundle_intermediate" },
      update: {},
      create: {
        id: "python_bundle_intermediate",
        courseName: "Python Bundle (Beginner → Intermediate)",
        token: 50,
        price: new Prisma.Decimal("1899.00"),
        imageUrl: "https://images.unsplash.com/photo-1526379095098-d400fd0bf935?w=400",
        description: "Upgrade your Python skills step by step. Learn: File handling, exception handling, dictionaries, OOP basics. Projects: Student Report Generator, Web Scraper",
        category: Category.PROGRAMMING,
        difficulty: Difficulty.INTERMEDIATE,
        durationHours: 50,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.6"),
        reviewCount: 800,
        tags: {
          connect: [{ id: tags[1].id }, { id: tags[2].id }, { id: tags[4].id }],
        },
      },
    }),
    prisma.course.upsert({
      where: { id: "python_pro_bundle" },
      update: {},
      create: {
        id: "python_pro_bundle",
        courseName: "Python Pro Bundle (Beginner → Advanced)",
        token: 65,
        price: new Prisma.Decimal("2599.00"),
        imageUrl: "https://images.unsplash.com/photo-1526379095098-d400fd0bf935?w=400",
        description: "Become job-ready with advanced Python. Learn: Advanced OOP, decorators, generators, NumPy, Pandas, Matplotlib, Flask. Projects: Blog Website, Data Analysis, Automation Scripts",
        category: Category.PROGRAMMING,
        difficulty: Difficulty.ADVANCED,
        durationHours: 90,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.8"),
        reviewCount: 600,
        tags: {
          connect: [{ id: tags[1].id }, { id: tags[2].id }, { id: tags[3].id }, { id: tags[4].id }],
        },
      },
    }),
    // Java & DSA Track Courses
    prisma.course.upsert({
      where: { id: "java_beginner" },
      update: {},
      create: {
        id: "java_beginner",
        courseName: "Java Beginner",
        token: 20,
        price: new Prisma.Decimal("1299.00"),
        imageUrl: "https://images.unsplash.com/photo-1517077304055-6e89abbf09b0?w=400",
        description: "Perfect for coding beginners who want to start with Java. Learn: Variables, loops, conditions, functions, arrays, strings. Hands-on: Mini projects (Calculator, Tic-Tac-Toe)",
        category: Category.PROGRAMMING,
        difficulty: Difficulty.BEGINNER,
        durationHours: 25,
        language: "English",
        isFeatured: false,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.4"),
        reviewCount: 950,
        tags: {
          connect: [{ id: tags[0].id }, { id: tags[2].id }],
        },
      },
    }),
    prisma.course.upsert({
      where: { id: "java_bundle_dsa" },
      update: {},
      create: {
        id: "java_bundle_dsa",
        courseName: "Java Bundle (Beginner → Intermediate DSA)",
        token: 50,
        price: new Prisma.Decimal("1899.00"),
        imageUrl: "https://images.unsplash.com/photo-1517077304055-6e89abbf09b0?w=400",
        description: "Step up your coding with Java + core Data Structures. Learn: Beginner topics + Recursion, Linked List, Stack, Queue, Searching & Sorting algorithms. Projects: Student Record System, Algorithm Visualizer",
        category: Category.PROGRAMMING,
        difficulty: Difficulty.INTERMEDIATE,
        durationHours: 55,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.7"),
        reviewCount: 700,
        tags: {
          connect: [{ id: tags[1].id }, { id: tags[2].id }, { id: tags[4].id }],
        },
      },
    }),
    prisma.course.upsert({
      where: { id: "java_pro_bundle_advanced_dsa" },
      update: {},
      create: {
        id: "java_pro_bundle_advanced_dsa",
        courseName: "Java Pro Bundle (Beginner → Advanced DSA)",
        token: 65,
        price: new Prisma.Decimal("2599.00"),
        imageUrl: "https://images.unsplash.com/photo-1517077304055-6e89abbf09b0?w=400",
        description: "Become job-ready with advanced Java + DSA. Learn: Intermediate topics + Trees, Graphs, Dynamic Programming, Backtracking, Advanced OOP (inheritance, polymorphism). Projects: E-commerce Backend Simulation, Competitive Programming Challenges",
        category: Category.PROGRAMMING,
        difficulty: Difficulty.ADVANCED,
        durationHours: 95,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.9"),
        reviewCount: 500,
        tags: {
          connect: [{ id: tags[1].id }, { id: tags[2].id }, { id: tags[3].id }, { id: tags[4].id }],
        },
      },
    }),
    // Web Development Track Courses
    prisma.course.upsert({
      where: { id: "web_dev_beginner" },
      update: {},
      create: {
        id: "web_dev_beginner",
        courseName: "Web Dev Beginner",
        token: 20,
        price: new Prisma.Decimal("1299.00"),
        imageUrl: "https://images.unsplash.com/photo-1627398242454-45a1465c2479?w=400",
        description: "Perfect for beginners exploring the world of websites. Learn: HTML, CSS, JavaScript basics, responsive design. Hands-on: Personal Portfolio Website",
        category: Category.WEB_DEVELOPMENT,
        difficulty: Difficulty.BEGINNER,
        durationHours: 25,
        language: "English",
        isFeatured: false,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.4"),
        reviewCount: 1200,
        tags: {
          connect: [{ id: tags[0].id }, { id: tags[2].id }],
        },
      },
    }),
    prisma.course.upsert({
      where: { id: "web_dev_bundle_intermediate" },
      update: {},
      create: {
        id: "web_dev_bundle_intermediate",
        courseName: "Web Dev Bundle (Beginner → Intermediate)",
        token: 50,
        price: new Prisma.Decimal("1899.00"),
        imageUrl: "https://images.unsplash.com/photo-1627398242454-45a1465c2479?w=400",
        description: "Build modern, dynamic websites with ease. Learn: Beginner topics + DOM manipulation, Bootstrap, Git & GitHub, Node.js basics, REST APIs. Projects: Blogging Platform, To-Do App with Database",
        category: Category.WEB_DEVELOPMENT,
        difficulty: Difficulty.INTERMEDIATE,
        durationHours: 55,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.6"),
        reviewCount: 850,
        tags: {
          connect: [{ id: tags[1].id }, { id: tags[2].id }, { id: tags[4].id }],
        },
      },
    }),
    prisma.course.upsert({
      where: { id: "web_dev_pro_bundle_fullstack" },
      update: {},
      create: {
        id: "web_dev_pro_bundle_fullstack",
        courseName: "Web Dev Pro Bundle (Beginner → Advanced Full-Stack)",
        token: 65,
        price: new Prisma.Decimal("2599.00"),
        imageUrl: "https://images.unsplash.com/photo-1627398242454-45a1465c2479?w=400",
        description: "Master full-stack web development and become job-ready. Learn: Intermediate topics + Express.js, MongoDB, Authentication, React.js, Deployment (Vercel/Netlify). Projects: E-commerce Store, Chat Application, Full-stack MERN App",
        category: Category.WEB_DEVELOPMENT,
        difficulty: Difficulty.ADVANCED,
        durationHours: 95,
        language: "English",
        isFeatured: true,
        mentorId: mentor.id,
        ratingAverage: new Prisma.Decimal("4.8"),
        reviewCount: 650,
        tags: {
          connect: [{ id: tags[1].id }, { id: tags[2].id }, { id: tags[3].id }, { id: tags[4].id }],
        },
      },
    }),
  ]);
  console.log("✅ Created courses");

  // --- Lessons for Python Beginner Course ---
  const lessons = await Promise.all([
    prisma.lesson.upsert({
      where: { id: "lesson-1" },
      update: {},
      create: {
        id: "lesson-1",
        title: "Introduction to Python",
        description: "Learn the basics of Python programming language and why it's perfect for beginners.",
        content: "Python is a powerful, easy-to-learn programming language that's perfect for beginners. In this lesson, we'll explore what makes Python special and set up your development environment.",
        videoUrl: "https://example.com/python-intro",
        durationMin: 45,
        order: 1,
        isPreview: true,
        courseId: courses[0].id,
      },
    }),
    prisma.lesson.upsert({
      where: { id: "lesson-2" },
      update: {},
      create: {
        id: "lesson-2",
        title: "Variables and Data Types in Python",
        description: "Understanding Python variables, strings, numbers, and basic data types.",
        content: "Variables in Python are containers for storing data. Learn about different data types including strings, integers, floats, and booleans. Practice with hands-on examples.",
        videoUrl: "https://example.com/python-variables",
        durationMin: 50,
        order: 2,
        isPreview: false,
        courseId: courses[0].id,
      },
    }),
    prisma.lesson.upsert({
      where: { id: "lesson-3" },
      update: {},
      create: {
        id: "lesson-3",
        title: "Loops and Control Structures",
        description: "Master Python loops (for, while) and conditional statements (if, elif, else).",
        content: "Control structures are fundamental to programming. Learn how to use if statements, loops, and make decisions in your code. Build your first interactive programs.",
        videoUrl: "https://example.com/python-loops",
        durationMin: 55,
        order: 3,
        isPreview: false,
        courseId: courses[0].id,
      },
    }),
    prisma.lesson.upsert({
      where: { id: "lesson-4" },
      update: {},
      create: {
        id: "lesson-4",
        title: "Functions in Python",
        description: "Learn to create reusable functions and organize your code efficiently.",
        content: "Functions are reusable blocks of code that perform specific tasks. Learn how to define functions, pass parameters, return values, and organize your code professionally.",
        videoUrl: "https://example.com/python-functions",
        durationMin: 60,
        order: 4,
        isPreview: false,
        courseId: courses[0].id,
      },
    }),
    prisma.lesson.upsert({
      where: { id: "lesson-5" },
      update: {},
      create: {
        id: "lesson-5",
        title: "Mini Project: Calculator App",
        description: "Build your first Python project - a fully functional calculator application.",
        content: "Put your Python skills to practice by building a calculator app. This hands-on project will reinforce everything you've learned and give you confidence in your programming abilities.",
        videoUrl: "https://example.com/python-calculator-project",
        durationMin: 90,
        order: 5,
        isPreview: false,
        courseId: courses[0].id,
      },
    }),
  ]);
  console.log("✅ Created lessons");

  // --- Student User ---
  const student = await prisma.user.upsert({
    where: { email: "student@example.com" },
    update: {},
    create: {
      id: "student-uuid-1",
      email: "student@example.com",
      fullName: "John Doe",
      userType: UserType.STUDENT,
      emailVerified: new Date(),
      isVerified: true,
      bio: "Aspiring developer learning new technologies.",
    },
  });
  console.log("✅ Created student");

  // --- Enrollment ---
  const enrollment = await prisma.enrollment.upsert({
    where: { 
      userId_courseId: {
        userId: student.id,
        courseId: courses[0].id
      }
    },
    update: {},
    create: {
      id: "enroll-1",
      userId: student.id,
      courseId: courses[0].id,
      progressPercent: new Prisma.Decimal("33.33"),
      status: EnrollmentStatus.ACTIVE,
      lastAccessedAt: new Date(),
    },
  });
  console.log("✅ Created enrollment");

  // --- Lesson Progress ---
  await prisma.lessonProgress.upsert({
    where: { 
      enrollmentId_lessonId: {
        enrollmentId: enrollment.id,
        lessonId: lessons[0].id
      }
    },
    update: {},
    create: {
      id: "lp-1",
      enrollmentId: enrollment.id,
      lessonId: lessons[0].id,
      completed: true,
      completedAt: new Date(),
      timeSpentMin: 25,
    },
  });
  console.log("✅ Created lesson progress");

  // --- Purchase ---
  const purchase = await prisma.purchase.upsert({
    where: { id: "purchase-1" },
    update: {},
    create: {
      id: "purchase-1",
      userId: student.id,
      totalAmount: new Prisma.Decimal(courses[0].price),
      status: PaymentStatus.COMPLETED,
    },
  });

  // --- Purchase Item ---
  await prisma.purchaseItem.upsert({
    where: { id: "purchase-item-1" },
    update: {},
    create: {
      id: "purchase-item-1",
      purchaseId: purchase.id,
      courseId: courses[0].id,
      purchasePrice: new Prisma.Decimal(courses[0].price),
    },
  });

  // --- Payment ---
  await prisma.payment.upsert({
    where: { providerPaymentId: "pay_mock_123456789" },
    update: {},
    create: {
      id: "payment-1",
      purchaseId: purchase.id,
      amount: new Prisma.Decimal(courses[0].price),
      currency: "INR",
      status: PaymentStatus.COMPLETED,
      provider: "razorpay",
      providerPaymentId: "pay_mock_123456789",
      providerOrderId: "order_mock_123456789",
    },
  });
  console.log("✅ Created purchase, purchase item, and payment");

  // --- Review ---
  await prisma.review.upsert({
    where: { 
      userId_courseId: {
        userId: student.id,
        courseId: courses[0].id
      }
    },
    update: {},
    create: {
      id: "review-1",
      userId: student.id,
      courseId: courses[0].id,
      rating: 5,
      comment:
        "Excellent course! Very well structured and easy to follow. The instructor explains concepts clearly.",
    },
  });
  console.log("✅ Created review");

  // --- Analytics ---
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  await Promise.all([
    prisma.analytics.upsert({
      where: { 
        date_metric: { 
          date: today, 
          metric: AnalyticMetric.DAILY_ACTIVE_USERS 
        } 
      },
      update: {},
      create: {
        date: today,
        metric: AnalyticMetric.DAILY_ACTIVE_USERS,
        value: new Prisma.Decimal("1250"),
      },
    }),
    prisma.analytics.upsert({
      where: { 
        date_metric: { 
          date: today, 
          metric: AnalyticMetric.NEW_REGISTRATIONS 
        } 
      },
      update: {},
      create: {
        date: today,
        metric: AnalyticMetric.NEW_REGISTRATIONS,
        value: new Prisma.Decimal("25"),
      },
    }),
    prisma.analytics.upsert({
      where: { 
        date_metric: { 
          date: today, 
          metric: AnalyticMetric.REVENUE 
        } 
      },
      update: {},
      create: {
        date: today,
        metric: AnalyticMetric.REVENUE,
        value: new Prisma.Decimal("15999.96"),
      },
    }),
    prisma.analytics.upsert({
      where: { 
        date_metric: { 
          date: today, 
          metric: AnalyticMetric.COURSE_ENROLLMENTS 
        } 
      },
      update: {},
      create: {
        date: today,
        metric: AnalyticMetric.COURSE_ENROLLMENTS,
        value: new Prisma.Decimal("1"),
      },
    }),
  ]);
  console.log("✅ Created analytics");

  // --- Notifications ---
  await prisma.notification.upsert({
    where: { id: "notif-1" },
    update: {},
    create: {
      id: "notif-1",
      userId: student.id,
      title: "Welcome to Skillyug!",
      message: "Thank you for joining our learning platform. Start your journey today!",
      type: NotificationType.SYSTEM_ANNOUNCEMENT,
      read: false,
    },
  });

  await prisma.notification.upsert({
    where: { id: "notif-2" },
    update: {},
    create: {
      id: "notif-2",
      userId: student.id,
      title: "Payment Successful",
      message: "Your payment for Python Beginner has been processed successfully.",
      type: NotificationType.PAYMENT_SUCCESS,
      read: false,
    },
  });
  console.log("✅ Created notifications");

  // --- Discussion Thread ---
  const discussionThread = await prisma.discussionThread.upsert({
    where: { id: "thread-1" },
    update: {},
    create: {
      id: "thread-1",
      title: "Question about JavaScript Variables",
      content: "Can someone explain the difference between let, const, and var?",
      userId: student.id,
      lessonId: lessons[1].id, // Variables and Data Types lesson
    },
  });

  // --- Discussion Post (Reply) ---
  await prisma.discussionPost.upsert({
    where: { id: "post-1" },
    update: {},
    create: {
      id: "post-1",
      content: "Great question! `let` and `const` are block-scoped, while `var` is function-scoped. `const` cannot be reassigned, but `let` can be.",
      userId: mentor.id,
      threadId: discussionThread.id,
    },
  });
  console.log("✅ Created discussion thread and post");

  // --- Bundles ---
  const pythonBundle = await prisma.bundle.upsert({
    where: { id: "python-track-bundle" },
    update: {},
    create: {
      id: "python-track-bundle",
      name: "Complete Python Development Track",
      description: "Master Python from beginner to advanced with data science and web development",
      price: new Prisma.Decimal("4999.00"),
      imageUrl: "https://images.unsplash.com/photo-1526379095098-d400fd0bf935?w=400",
      isActive: true,
    },
  });

  const javaBundle = await prisma.bundle.upsert({
    where: { id: "java-dsa-track-bundle" },
    update: {},
    create: {
      id: "java-dsa-track-bundle",
      name: "Complete Java & DSA Mastery Track",
      description: "Become a competitive programmer and enterprise Java developer",
      price: new Prisma.Decimal("4999.00"),
      imageUrl: "https://images.unsplash.com/photo-1517077304055-6e89abbf09b0?w=400",
      isActive: true,
    },
  });

  const webDevBundle = await prisma.bundle.upsert({
    where: { id: "webdev-track-bundle" },
    update: {},
    create: {
      id: "webdev-track-bundle",
      name: "Complete Full-Stack Web Development Track",
      description: "Build modern web applications from frontend to backend",
      price: new Prisma.Decimal("4999.00"),
      imageUrl: "https://images.unsplash.com/photo-1627398242454-45a1465c2479?w=400",
      isActive: true,
    },
  });

  // --- Course Bundle Associations ---
  // Python Track Bundle
  await Promise.all([
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[0].id, // python_beginner
          bundleId: pythonBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[0].id,
        bundleId: pythonBundle.id,
      },
    }),
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[1].id, // python_bundle_intermediate
          bundleId: pythonBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[1].id,
        bundleId: pythonBundle.id,
      },
    }),
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[2].id, // python_pro_bundle
          bundleId: pythonBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[2].id,
        bundleId: pythonBundle.id,
      },
    }),
  ]);

  // Java Track Bundle
  await Promise.all([
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[3].id, // java_beginner
          bundleId: javaBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[3].id,
        bundleId: javaBundle.id,
      },
    }),
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[4].id, // java_bundle_dsa
          bundleId: javaBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[4].id,
        bundleId: javaBundle.id,
      },
    }),
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[5].id, // java_pro_bundle_advanced_dsa
          bundleId: javaBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[5].id,
        bundleId: javaBundle.id,
      },
    }),
  ]);

  // Web Dev Track Bundle
  await Promise.all([
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[6].id, // web_dev_beginner
          bundleId: webDevBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[6].id,
        bundleId: webDevBundle.id,
      },
    }),
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[7].id, // web_dev_bundle_intermediate
          bundleId: webDevBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[7].id,
        bundleId: webDevBundle.id,
      },
    }),
    prisma.courseBundle.upsert({
      where: { 
        courseId_bundleId: {
          courseId: courses[8].id, // web_dev_pro_bundle_fullstack
          bundleId: webDevBundle.id
        }
      },
      update: {},
      create: {
        courseId: courses[8].id,
        bundleId: webDevBundle.id,
      },
    }),
  ]);
  console.log("✅ Created bundles and course associations");

  // --- Learning Paths ---
  const pythonLearningPath = await prisma.learningPath.upsert({
    where: { id: "python-learning-path" },
    update: {},
    create: {
      id: "python-learning-path",
      title: "Python Development Track",
      description: "Complete Python journey from beginner to professional developer",
    },
  });

  const javaLearningPath = await prisma.learningPath.upsert({
    where: { id: "java-dsa-learning-path" },
    update: {},
    create: {
      id: "java-dsa-learning-path",
      title: "Java & DSA Mastery Track",
      description: "Master Java programming and data structures & algorithms",
    },
  });

  const webDevLearningPath = await prisma.learningPath.upsert({
    where: { id: "webdev-learning-path" },
    update: {},
    create: {
      id: "webdev-learning-path",
      title: "Full-Stack Web Development Track",
      description: "Build modern web applications from frontend to backend",
    },
  });

  console.log("✅ Created learning paths");

  console.log("🎉 Database seed completed successfully!");

  // --- Summary ---
  const coursesCount = await prisma.course.count();
  const usersCount = await prisma.user.count();
  const enrollmentsCount = await prisma.enrollment.count();
  const purchasesCount = await prisma.purchase.count();
  const reviewsCount = await prisma.review.count();
  const notificationsCount = await prisma.notification.count();
  const bundlesCount = await prisma.bundle.count();
  const learningPathsCount = await prisma.learningPath.count();

  console.log("\n📊 Seed Summary:");
  console.log(`- Users: ${usersCount}`);
  console.log(`- Courses: ${coursesCount}`);
  console.log(`- Enrollments: ${enrollmentsCount}`);
  console.log(`- Purchases: ${purchasesCount}`);
  console.log(`- Reviews: ${reviewsCount}`);
  console.log(`- Notifications: ${notificationsCount}`);
  console.log(`- Course Tags: ${tags.length}`);
  console.log(`- Bundles: ${bundlesCount}`);
  console.log(`- Learning Paths: ${learningPathsCount}`);
}

main()
  .catch((e) => {
    console.error("❌ Seed failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
