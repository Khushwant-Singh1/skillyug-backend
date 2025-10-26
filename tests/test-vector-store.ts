#!/usr/bin/env tsx

import { VectorStoreService } from './src/services/recommendation/vectorStore.service';

async function testVectorStore() {
  console.log('🧪 Testing Vector Store Service...');
  
  try {
    const vectorStore = new VectorStoreService('localhost', 8000);
    
    // Initialize
    await vectorStore.initialize();
    
    // Index courses
    const catalogPath = '/home/anuragisinsane/skillyug/Backend/data/catalog/courses.json';
    await vectorStore.indexCourses(catalogPath);
    
    // Get stats
    const stats = await vectorStore.getStats();
    console.log('📊 Collection stats:', stats);
    
    // Test search
    console.log('\n🔍 Testing searches...');
    
    // Test 1: Python search
    const pythonResults = await vectorStore.searchCourses('python programming beginner');
    console.log(`\n1. Python search results: ${pythonResults.length}`);
    pythonResults.forEach((result, i) => {
      console.log(`   ${i+1}. ${result.metadata.title} (${result.metadata.level})`);
    });
    
    // Test 2: Backend search
    const backendResults = await vectorStore.searchCourses('backend development server');
    console.log(`\n2. Backend search results: ${backendResults.length}`);
    backendResults.forEach((result, i) => {
      console.log(`   ${i+1}. ${result.metadata.title} (${result.metadata.level})`);
    });
    
    // Test 3: Node.js search (should not find exact match)
    const nodeResults = await vectorStore.searchCourses('nodejs node.js javascript');
    console.log(`\n3. Node.js search results: ${nodeResults.length}`);
    nodeResults.forEach((result, i) => {
      console.log(`   ${i+1}. ${result.metadata.title} (${result.metadata.level})`);
    });
    
    console.log('\n✅ Vector store test completed successfully!');
    
  } catch (error) {
    console.error('❌ Vector store test failed:', error);
    
    // If ChromaDB is not running, provide setup instructions
    const errorMessage = error instanceof Error ? error.message : String(error);
    if (errorMessage.includes('ECONNREFUSED') || errorMessage.includes('connection')) {
      console.log('\n🚨 ChromaDB Connection Failed');
      console.log('To run ChromaDB locally:');
      console.log('1. pip install chromadb');
      console.log('2. chroma run --host localhost --port 8000');
      console.log('Or use Docker: docker run -p 8000:8000 chromadb/chroma');
    }
    
    process.exit(1);
  }
}

testVectorStore();