# Intelligent Course Recommendation System

A sophisticated RAG-based (Retrieval-Augmented Generation) microservice that provides intelligent course recommendations for the Skillyug platform.

## 🎯 Overview

This system accepts natural language queries from users, understands their learning intent, and provides personalized course recommendations. It uses advanced techniques including:

- **PDF Course Catalog Extraction** - Converts PDF catalogs to structured data
- **Vector Embeddings** - Using Google's EmbeddingGemma-300M model
- **Intent Parsing** - Rule-based and LLM-powered user intent extraction
- **RAG Pipeline** - Retrieval-Augmented Generation for intelligent responses
- **Business Logic** - Smart fallback recommendations with persuasive messaging

## 🏗️ Architecture

```
User Query → Intent Parser → Vector Search → Business Rules → LLM Generation → Response
     ↓            ↓              ↓              ↓              ↓
  "I want      {goal:         Course        Exact match    Markdown
  Node.js      "backend",     candidates     detection      response
  backend"     language:      from vector    & ranking      with CTAs
               "nodejs"}      store
```

## 📁 Project Structure

```
Backend/
├── src/
│   ├── services/recommendation/
│   │   ├── recommendation.service.ts    # Main orchestrator
│   │   ├── intentParser.service.ts      # User intent extraction
│   │   ├── vectorStore.service.ts       # ChromaDB integration
│   │   └── inMemoryVectorStore.service.ts # Fallback vector store
│   ├── controllers/recommendation/
│   │   └── recommendation.controller.ts # HTTP request handling
│   ├── router/recommendation/
│   │   └── recommendation.router.ts     # API route definitions
│   ├── utils/pdf/
│   │   └── extractor.ts                 # PDF catalog extraction
│   ├── types/
│   │   └── recommendation.types.ts      # TypeScript interfaces
│   └── validators/
│       └── recommendation.validator.ts  # Request validation
├── data/
│   ├── catalog/courses.json            # Extracted course catalog
│   └── vectors/                        # Vector embeddings storage
└── tests/
    ├── test-pdf-extraction.ts          # PDF extraction tests
    ├── test-recommendation-system.ts   # End-to-end system tests
    └── test-api.ts                     # API endpoint tests
```

## 🚀 Quick Start

### 1. Extract Course Catalog

```bash
cd Backend
pnpm dlx tsx test-pdf-extraction.ts
```

This extracts courses from the PDF and saves to `data/catalog/courses.json`.

### 2. Test the System

```bash
pnpm dlx tsx test-recommendation-system.ts
```

This tests the complete recommendation pipeline end-to-end.

### 3. Test the API

Start the server:
```bash
pnpm dev
```

Test the API:
```bash
pnpm dlx tsx test-api.ts
```

## 📡 API Endpoints

### POST /api/recommend

Generate course recommendations based on user input.

**Request:**
```json
{
  "text": "I want to become a backend engineer; I prefer Node.js",
  "chips": ["backend", "nodejs", "intermediate"],
  "user": { "id": "optional" }
}
```

**Response:**
```json
{
  "markdown": "Great! I found a perfect match: **Node.js Backend Essentials**...",
  "candidates": [
    {
      "id": "course_nodejs_001",
      "title": "Node.js Backend Essentials",
      "score": 0.97,
      "reason": "Matches Node.js preference and backend goals",
      "course": { /* full course details */ }
    }
  ],
  "exactMatch": true,
  "intent": {
    "goal": "become a backend engineer",
    "preferredLanguage": "nodejs",
    "level": "intermediate",
    "confidence": 0.9
  },
  "analytics": {
    "reasonKeys": ["exact-match", "language-preference"],
    "candidateCount": 3,
    "confidence": 0.9
  }
}
```

### GET /api/recommend/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "initialized": true,
  "timestamp": "2024-03-15T10:30:00.000Z",
  "version": "1.0.0"
}
```

### POST /api/recommend/feedback

Submit user feedback on recommendations.

**Request:**
```json
{
  "requestId": "req_123",
  "courseId": "course_python_001",
  "action": "enroll",
  "rating": 5,
  "comments": "Great recommendation!"
}
```

## 🧠 Intent Parsing

The system uses a two-stage intent parsing approach:

### 1. Rule-Based Extraction

Regex patterns detect:
- **Job roles**: backend, frontend, data science, etc.
- **Languages**: Python, Node.js, Java, etc.
- **Skill levels**: beginner, intermediate, advanced
- **Budget constraints**: ₹1000, under 2000, etc.
- **Format preferences**: bootcamp, self-paced, live

### 2. LLM Fallback

When rule-based confidence is low (<0.8), the system uses Google's Gemma-3-270M for more nuanced understanding.

## 🎯 Business Logic

### Exact Match Detection
If user's preferred language exists in course catalog → Return exact match with strong CTA

### Fallback Strategy
If no exact match → Persuasive response emphasizing:
- Transferable skills (architecture, design patterns, APIs)
- Long-term career benefits
- Easy transition to preferred language later
- Optional upsells (notifications, bridge modules)

### Scoring Algorithm
```
Final Score = 0.6 × Vector Similarity + 0.4 × Exact Topic Match + Boosts

Boosts:
- Language match: +0.3
- Level match: +0.2
- Format match: +0.1
- Budget penalty: -0.2 (if over budget)
```

## 🗂️ Course Catalog Schema

```typescript
interface CourseRecord {
  id: string;                    // "course_python_beginner_001"
  title: string;                 // "Python Beginner"
  slug: string;                  // "python-beginner"
  description: string;           // Course description
  topics: string[];              // ["python", "programming", "beginner"]
  level: "beginner" | "intermediate" | "advanced";
  language: string;              // "en"
  price: number;                 // 1299
  currency: string;              // "INR"
  availability: boolean;         // true
  format: "self-paced" | "live" | "bootcamp";
  perks: string[];              // ["30% refund via scholarship test"]
  metadata: {
    duration: string;            // "40 hours"
    boots: string;              // "2 bootcamps"
  };
}
```

## 🐳 Docker Setup

The system includes ChromaDB for production vector storage:

### Development
```bash
make dev  # Includes in-memory fallback
```

### Production
```bash
make prod  # Uses persistent ChromaDB
```

**Services:**
- **Backend**: Main API service
- **ChromaDB**: Vector database (persistent)
- **PostgreSQL**: Main database
- **Redis**: Caching

## ⚡ Performance

### Response Times
- **Intent parsing**: ~100ms
- **Vector search**: ~50ms (ChromaDB) / ~10ms (in-memory)
- **LLM generation**: ~500ms (with API key) / ~5ms (fallback)
- **Total**: ~650ms (full pipeline)

### Caching
- Embeddings cached for repeated queries
- Course catalog loaded once on startup
- Vector store persisted between restarts

## 🔧 Configuration

### Environment Variables

```bash
# Optional: For production-grade embeddings and generation
HUGGINGFACE_API_KEY=your_hf_token_here

# ChromaDB (automatically configured in Docker)
CHROMADB_URL=http://chromadb:8000

# Falls back to in-memory store and mock embeddings if not provided
```

## 📊 Monitoring & Analytics

The system tracks:
- **Request patterns**: Top queries, user intents
- **Recommendation quality**: Exact matches vs fallbacks
- **User feedback**: Ratings, actions (enroll/dismiss)
- **Performance metrics**: Response times, error rates

Access analytics via:
```bash
GET /api/recommend/stats  # Admin only
```

## 🧪 Testing

### Unit Tests
```bash
pnpm dlx tsx test-pdf-extraction.ts      # PDF extraction
pnpm dlx tsx test-vector-store.ts        # Vector operations
```

### Integration Tests
```bash
pnpm dlx tsx test-recommendation-system.ts  # Full pipeline
pnpm dlx tsx test-api.ts                    # HTTP endpoints
```

### Test Cases Covered
- ✅ PDF to JSON extraction
- ✅ Intent parsing (high/low confidence)
- ✅ Vector similarity search
- ✅ Exact match detection
- ✅ Fallback recommendations
- ✅ Business rule application
- ✅ Response generation
- ✅ API validation
- ✅ Error handling

## 🚀 Production Deployment

1. **Set environment variables** (HuggingFace API key recommended)
2. **Start services**: `make prod`
3. **Verify health**: `curl http://localhost:5000/api/recommend/health`
4. **Monitor logs** for initialization and first requests

## 🔄 Maintenance

### Reindexing Catalog
When course catalog changes:
```bash
POST /api/recommend/reindex  # Admin only
```

### Updating Embeddings
The system automatically recomputes embeddings when courses change.

## 📈 Roadmap

- [ ] **A/B Testing**: Compare rule-based vs LLM-only intent parsing
- [ ] **User Clustering**: Group users by learning patterns
- [ ] **Dynamic Pricing**: Adjust recommendations based on demand
- [ ] **Multi-language Support**: Hindi and regional language courses
- [ ] **Skill Path Recommendations**: Sequential course progressions
- [ ] **Integration with LMS**: Real-time progress-based suggestions

## 🤝 Contributing

1. **Add new intent patterns** in `intentParser.service.ts`
2. **Improve business rules** in `recommendation.service.ts`
3. **Extend course schema** in `recommendation.types.ts`
4. **Add test cases** for new functionality

---

**Built with**: Node.js, TypeScript, ChromaDB, HuggingFace Transformers, Express.js, Docker

**Status**: ✅ Production Ready