import { Router } from 'express';
import { preprocessCode } from '../preprocessors/code.js';
import { preprocessPackage } from '../preprocessors/package.js';
import { preprocessUrl } from '../preprocessors/url.js';
import { codeAnalystPrompt } from '../prompts/codeAnalyst.js';
import { packageAnalystPrompt } from '../prompts/packageAnalyst.js';
import { urlAnalystPrompt } from '../prompts/urlAnalyst.js';
import { analyzeWithGemini } from '../services/gemini.js';

const router = Router();

const VALID_TYPES = ['code', 'package', 'url'];

const pipeline = {
    code: { preprocess: preprocessCode, prompt: codeAnalystPrompt },
    package: { preprocess: preprocessPackage, prompt: packageAnalystPrompt },
    url: { preprocess: preprocessUrl, prompt: urlAnalystPrompt },
};

router.post('/analyze', async (req, res, next) => {
    try {
        const { type, content } = req.body;

        // --- Input Validation ---
        if (!type || !content) {
            return res.status(400).json({
                error: true,
                message: 'Both "type" and "content" fields are required.',
            });
        }

        if (!VALID_TYPES.includes(type)) {
            return res.status(400).json({
                error: true,
                message: `Invalid type "${type}". Must be one of: ${VALID_TYPES.join(', ')}`,
            });
        }

        if (typeof content !== 'string' || content.trim().length === 0) {
            return res.status(400).json({
                error: true,
                message: '"content" must be a non-empty string.',
            });
        }

        // --- Pipeline ---
        const { preprocess, prompt } = pipeline[type];

        console.log(`\n🔍 Analyzing [${type.toUpperCase()}]: ${content.substring(0, 80)}...`);

        // Step 1: Pre-process the input
        const preprocessedData = await preprocess(content);
        console.log('  ✅ Pre-processing complete');

        // Step 2: Send to Gemini with the correct prompt
        const result = await analyzeWithGemini(prompt, preprocessedData);
        console.log('  ✅ AI analysis complete');

        // Step 3: Return result
        return res.json({
            error: false,
            type,
            result,
        });
    } catch (err) {
        next(err);
    }
});

export default router;
