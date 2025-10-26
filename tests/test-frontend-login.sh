#!/bin/bash

# Test login request similar to what frontend sends
echo "🧪 Testing frontend-style login request..."

curl -X POST http://localhost:5000/api/auth/login-check \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3001" \
  -H "User-Agent: Mozilla/5.0 (compatible; Frontend-Test)" \
  -d '{
    "email": "khushzx8630@gmail.com",
    "password": "password123"
  }' \
  -v

echo -e "\n\n🧪 Testing with a different user that might exist..."

curl -X POST http://localhost:5000/api/auth/login-check \
  -H "Content-Type: application/json" \
  -H "Origin: http://localhost:3001" \
  -H "User-Agent: Mozilla/5.0 (compatible; Frontend-Test)" \
  -d '{
    "email": "frontend@test.com",
    "password": "testpassword"
  }' \
  -v
