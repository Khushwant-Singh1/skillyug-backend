#!/usr/bin/env tsx

import axios from 'axios';

/**
 * Simple API test for the recommendation endpoint
 * Run this after starting the server to test the API
 */
async function testRecommendationAPI() {
  console.log('🧪 Testing Recommendation API...');
  
  const baseURL = 'http://localhost:5000';
  
  // Test cases
  const testCases = [
    {
      name: 'Health Check',
      method: 'GET',
      endpoint: '/api/recommend/health',
      data: null
    },
    {
      name: 'Python Backend Request',
      method: 'POST',
      endpoint: '/api/recommend',
      data: {
        text: 'I want to become a backend engineer and prefer Python',
        chips: ['backend', 'python', 'beginner'],
        user: { id: 'test-user-1' }
      }
    },
    {
      name: 'Node.js Request (No Match)',
      method: 'POST', 
      endpoint: '/api/recommend',
      data: {
        text: 'I want to learn Node.js for server development',
        chips: ['nodejs', 'backend'],
        user: { id: 'test-user-2' }
      }
    },
    {
      name: 'General Programming Request',
      method: 'POST',
      endpoint: '/api/recommend',
      data: {
        text: 'I want to learn programming',
        chips: ['programming', 'beginner']
      }
    }
  ];

  let passedTests = 0;
  let totalTests = testCases.length;

  for (const testCase of testCases) {
    console.log(`\n🎯 Testing: ${testCase.name}`);
    
    try {
      const config = {
        method: testCase.method.toLowerCase(),
        url: `${baseURL}${testCase.endpoint}`,
        data: testCase.data,
        timeout: 30000,
        headers: {
          'Content-Type': 'application/json'
        }
      };

      const response = await axios(config);
      
      console.log(`   ✅ Status: ${response.status}`);
      
      if (testCase.endpoint === '/api/recommend/health') {
        console.log(`   📊 Health: ${response.data.status}`);
        console.log(`   🔧 Initialized: ${response.data.initialized}`);
      } else {
        console.log(`   🎯 Candidates: ${response.data.candidates?.length || 0}`);
        console.log(`   🧠 Intent: ${response.data.intent?.goal || 'unknown'}`);
        console.log(`   ✨ Exact Match: ${response.data.exactMatch ? '✅' : '❌'}`);
        
        if (response.data.markdown) {
          const preview = response.data.markdown.substring(0, 100);
          console.log(`   💬 Response: "${preview}${response.data.markdown.length > 100 ? '...' : ''}"`);
        }
      }
      
      passedTests++;
      
    } catch (error: any) {
      console.log(`   ❌ Failed: ${error.response?.status || error.code}`);
      
      if (error.response?.data) {
        console.log(`   📝 Error: ${error.response.data.message || error.response.data.error}`);
      } else if (error.code === 'ECONNREFUSED') {
        console.log('   🚨 Connection refused - make sure the server is running on port 5000');
        console.log('   💡 Try: cd Backend && pnpm dev');
      }
    }
  }

  console.log(`\n📊 Test Summary: ${passedTests}/${totalTests} tests passed`);
  
  if (passedTests === totalTests) {
    console.log('✅ All tests passed! The recommendation API is working correctly.');
  } else {
    console.log('❌ Some tests failed. Check the errors above.');
  }

  // Additional endpoint information
  console.log('\n📋 Available Endpoints:');
  console.log('   GET  /api/recommend/health     - Health check');
  console.log('   POST /api/recommend            - Get recommendations');
  console.log('   POST /api/recommend/feedback   - Submit feedback');
  console.log('   GET  /api/recommend/stats      - Get statistics (admin)');
  console.log('   POST /api/recommend/reindex    - Reindex catalog (admin)');
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

testRecommendationAPI();