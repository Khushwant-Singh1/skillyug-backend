import axios, { AxiosInstance } from 'axios'

const ENGINE_URL = process.env.RECOMMENDER_URL || 'http://localhost:8003'
const ENGINE_TIMEOUT_MS = Number(process.env.RECOMMENDER_TIMEOUT_MS || 4000)

export interface IntentRequest {
  query: string
  chips?: string[]
  userContext?: Record<string, unknown>
  locale?: string
  max_results?: number
}

export interface RecommendationItem {
  course_stub: string
  title: string
  level?: string
  match_type: 'exact' | 'similar' | 'fallback'
  confidence: number
  reasoning?: string
  features?: string[]
  persuasive_copy?: string
}

export interface EngineResponse {
  success: boolean
  data: {
    intent: string
    match_summary: 'exact' | 'similar' | 'fallback'
    recommendations: RecommendationItem[]
  }
  meta?: Record<string, unknown>
}

class RecommendationService {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: ENGINE_URL,
      timeout: ENGINE_TIMEOUT_MS,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  async recommend(payload: IntentRequest): Promise<EngineResponse> {
    try {
      const { data } = await this.client.post<EngineResponse>('/api/recommendations/backend', {
        query: payload.query,
        chips: payload.chips || [],
        userContext: payload.userContext || {},
        locale: payload.locale || 'en-IN',
        max_results: payload.max_results || 5
      })
      return data
    } catch (error) {
      console.error('Recommendation service error:', error)
      // Return fallback response
      return {
        success: false,
        data: {
          intent: 'unknown',
          match_summary: 'fallback',
          recommendations: []
        },
        meta: { error: 'Service temporarily unavailable' }
      }
    }
  }
}

export const recommendationService = new RecommendationService()
