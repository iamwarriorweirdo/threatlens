import 'dotenv/config';
import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import analyzeRouter from './routes/analyze.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json({ limit: '1mb' }));

// API Routes
app.use('/api', analyzeRouter);

// Serve static frontend
app.use(express.static(join(__dirname, '..', 'public')));
app.get('*', (req, res) => {
    res.sendFile(join(__dirname, '..', 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.message);
    res.status(500).json({
        error: true,
        message: process.env.NODE_ENV === 'production'
            ? 'Internal server error'
            : err.message,
    });
});

app.listen(PORT, () => {
    console.log(`\n🛡️  ThreatLens API running on http://localhost:${PORT}`);
    console.log(`   Model: ${process.env.GEMINI_MODEL || 'gemini-2.0-flash'}`);
    console.log(`   API Key: ${process.env.GEMINI_API_KEY ? '✅ Set' : '❌ Missing!'}\n`);
});
