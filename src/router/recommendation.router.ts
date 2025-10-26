import { Router, Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import prisma from '../utils/prisma'
import { recommendationService, type IntentRequest, type EngineResponse } from '../services/recommendation.service'

const router = Router()

// Define interface for enriched recommendation items
interface EnrichedRecommendation {
  courseId: string;
  title: string;
  level: string;
  priceINR: number;
  imageUrl: string;
  category: string;
  rating: number;
  reviews: number;
  match_type: string;
  confidence: number;
  persuasive_copy: string;
  reasoning: string;
  features: string[];
  badge: string;
  cta: string;
}

// Input validation schema
const intentSchema = z.object({
  query: z.string().min(2),
  chips: z.array(z.string()).optional(),
  userContext: z.record(z.unknown()).optional(),
  locale: z.string().optional(),
  max_results: z.number().int().min(1).max(10).optional(),
})

// Map engine recommendation item to catalog item
async function validateAndEnrich(items: EngineResponse['data']['recommendations']) {
  const enriched: EnrichedRecommendation[] = []

  for (const item of items) {
    // NOTE: We do not have a slug/course_stub in DB yet. We use title fuzzy match for now.
    // Recommended: add `slug` or `courseStub` column to Course and ensure population.
    const course = await prisma.course.findFirst({
      where: {
        OR: [
          { courseName: { equals: item.title, mode: 'insensitive' } },
          { courseName: { contains: item.title.split(' ')[0], mode: 'insensitive' } },
        ],
        isActive: true,
      },
      select: {
        id: true,
        courseName: true,
        price: true,
        imageUrl: true,
        difficulty: true,
        category: true,
        ratingAverage: true,
        reviewCount: true,
      },
    })

    if (!course) {
      // Skip items not in catalog to maintain integrity
      continue
    }

    enriched.push({
      courseId: course.id,
      title: course.courseName,
      level: item.level ?? String(course.difficulty),
      priceINR: Number(course.price),
      imageUrl: course.imageUrl,
      category: String(course.category),
      rating: Number(course.ratingAverage),
      reviews: course.reviewCount,
      match_type: item.match_type,
      confidence: item.confidence,
      persuasive_copy: item.persuasive_copy || '',
      reasoning: item.reasoning || '',
      features: item.features || [],
      badge: item.match_type === 'exact' ? 'Best match' : item.match_type === 'similar' ? 'Great alternative' : 'Learn fundamentals',
      cta: 'Enroll now',
    })
  }

  return enriched
}

router.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = intentSchema.parse(req.body)

    const payload: IntentRequest = {
      query: parsed.query,
      chips: parsed.chips,
      userContext: parsed.userContext,
      locale: parsed.locale ?? 'en-IN',
      max_results: parsed.max_results ?? 5,
    }

    const engine = await recommendationService.recommend(payload)

    const items = await validateAndEnrich(engine.data.recommendations)

    // If no items passed catalog validation, craft a safe fallback
    if (!items.length) {
      return res.status(200).json({
        status: 'success',
        data: {
          intent: engine.data.intent,
          items: [],
          notes: [
            'We could not verify a matching course in our catalog right now.',
            'Tip: Try exploring backend design or Python backend—skills transfer seamlessly to Node.js.'
          ],
        },
        meta: engine.meta || {},
      })
    }

    return res.status(200).json({
      status: 'success',
      data: {
        intent: engine.data.intent,
        items,
        notes: [
          engine.data.match_summary === 'exact'
            ? 'Matched your Node.js backend preference.'
            : engine.data.match_summary === 'similar'
            ? 'Closest matches based on your goal and constraints.'
            : 'Master fundamentals first; switching stacks later is fast and effective.'
        ],
      },
      meta: engine.meta || {},
    })
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ status: 'fail', message: 'Invalid request', errors: error.errors })
    }
    next(error)
  }
})

router.get('/health', async (_req, res, next) => {
  try {
    // Proxy engine health for consolidated checks
    const axios = (await import('axios')).default
    const { data } = await axios.get(`${process.env.RECOMMENDER_URL || 'http://localhost:8003'}/health`, { timeout: 2000 })
    return res.status(200).json({ status: 'success', data })
  } catch (e) {
    next(e)
  }
})

export default router
