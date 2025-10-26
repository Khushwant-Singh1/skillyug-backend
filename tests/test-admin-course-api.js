// Test file for admin course API endpoints
// Run this with: node test-admin-api.js

const axios = require('axios');

const API_BASE_URL = 'http://localhost:5000/api';

// Test configuration
const testAdmin = {
  email: 'admin@test.com',
  password: 'password123'
};

let authToken = '';

// Helper function to make authenticated requests
const makeRequest = async (method, url, data = null) => {
  try {
    const config = {
      method,
      url: `${API_BASE_URL}${url}`,
      headers: {
        'Content-Type': 'application/json',
        ...(authToken && { 'Authorization': `Bearer ${authToken}` })
      },
      ...(data && { data })
    };

    const response = await axios(config);
    return response.data;
  } catch (error) {
    console.error(`Error with ${method} ${url}:`, error.response?.data || error.message);
    throw error;
  }
};

// Test functions
const testLogin = async () => {
  console.log('🔐 Testing admin login...');
  const response = await makeRequest('POST', '/auth/login', testAdmin);
  
  if (response.success && response.data.accessToken) {
    authToken = response.data.accessToken;
    console.log('✅ Admin login successful');
    return true;
  } else {
    console.log('❌ Admin login failed');
    return false;
  }
};

const testGetCourses = async () => {
  console.log('📚 Testing get all courses...');
  const response = await makeRequest('GET', '/courses');
  
  if (response.success) {
    console.log(`✅ Retrieved ${response.data?.length || 0} courses`);
    return response.data;
  } else {
    console.log('❌ Failed to get courses');
    return [];
  }
};

const testCreateCourse = async () => {
  console.log('➕ Testing create course...');
  const courseData = {
    title: 'Test Admin Course',
    description: 'This is a test course created by admin',
    category: 'TECH',
    difficulty: 'BEGINNER',
    price: 99.99,
    featured: true
  };

  const response = await makeRequest('POST', '/courses', courseData);
  
  if (response.success && response.data) {
    console.log('✅ Course created successfully:', response.data.id);
    return response.data;
  } else {
    console.log('❌ Failed to create course');
    return null;
  }
};

const testUpdateCourse = async (courseId) => {
  console.log('✏️ Testing update course...');
  const updateData = {
    title: 'Updated Test Course',
    price: 149.99,
    featured: false
  };

  const response = await makeRequest('PATCH', `/courses/${courseId}`, updateData);
  
  if (response.success) {
    console.log('✅ Course updated successfully');
    return response.data;
  } else {
    console.log('❌ Failed to update course');
    return null;
  }
};

const testDeleteCourse = async (courseId) => {
  console.log('🗑️ Testing delete course...');
  const response = await makeRequest('DELETE', `/courses/${courseId}`);
  
  if (response.success) {
    console.log('✅ Course deleted successfully');
    return true;
  } else {
    console.log('❌ Failed to delete course');
    return false;
  }
};

const testToggleFeatured = async (courseId) => {
  console.log('⭐ Testing toggle featured status...');
  const response = await makeRequest('PATCH', `/courses/${courseId}/featured`);
  
  if (response.success) {
    console.log('✅ Featured status toggled successfully');
    return response.data;
  } else {
    console.log('❌ Failed to toggle featured status');
    return null;
  }
};

// Main test runner
const runTests = async () => {
  console.log('🚀 Starting Admin Course API Tests...\n');

  try {
    // Step 1: Login as admin
    const loginSuccess = await testLogin();
    if (!loginSuccess) {
      console.log('❌ Cannot proceed without admin authentication');
      return;
    }

    console.log('');

    // Step 2: Get existing courses
    const existingCourses = await testGetCourses();
    console.log('');

    // Step 3: Create a new course
    const newCourse = await testCreateCourse();
    if (!newCourse) {
      console.log('❌ Cannot proceed without creating a course');
      return;
    }

    console.log('');

    // Step 4: Update the course
    await testUpdateCourse(newCourse.id);
    console.log('');

    // Step 5: Toggle featured status
    await testToggleFeatured(newCourse.id);
    console.log('');

    // Step 6: Get courses again to verify changes
    await testGetCourses();
    console.log('');

    // Step 7: Clean up - delete the test course
    await testDeleteCourse(newCourse.id);

    console.log('\n🎉 All tests completed!');

  } catch (error) {
    console.error('\n💥 Test suite failed:', error.message);
  }
};

// Run the tests
runTests();

module.exports = {
  runTests,
  testLogin,
  testGetCourses,
  testCreateCourse,
  testUpdateCourse,
  testDeleteCourse,
  testToggleFeatured
};