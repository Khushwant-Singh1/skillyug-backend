const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

console.log('⚠️  Running TEST SERVER - No database or payment gateway connected');
console.log('📝 This is for testing the basic setup only');

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        mode: 'test',
        timestamp: new Date().toISOString()
    });
});

// Mock Razorpay key endpoint
app.get('/api/getKey', (req, res) => {
    res.json({ key: 'test_razorpay_key' });
});

// Mock courses endpoint
app.get('/api/courses', (req, res) => {
    res.json({
        courses: [
            { id: 1, name: 'Test Course 1', price: 999 },
            { id: 2, name: 'Test Course 2', price: 1999 }
        ]
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.send(`
        <h1>Skillyug Backend - TEST MODE</h1>
        <p>Server is running on port ${PORT}</p>
        <h2>Status:</h2>
        <ul>
            <li>✅ Express Server: Running</li>
            <li>⚠️ MongoDB: Not connected (mock mode)</li>
            <li>⚠️ Razorpay: Not configured (mock mode)</li>
        </ul>
        <h2>Test Endpoints:</h2>
        <ul>
            <li><a href="/health">/health</a> - Health check</li>
            <li><a href="/api/getKey">/api/getKey</a> - Mock Razorpay key</li>
            <li><a href="/api/courses">/api/courses</a> - Mock courses</li>
        </ul>
        <p style="color: orange;">To connect real services, update the .env file</p>
    `);
});

// Start server
app.listen(PORT, () => {
    console.log(`✅ Test server is running on port ${PORT}`);
    console.log(`🌐 Open http://localhost:${PORT} in your browser`);
    console.log('');
    console.log('Frontend should be available at http://localhost:5173');
});
