import { GoogleGenerativeAI } from '@google/generative-ai';

const API_KEY = process.env.GEMINI_API_KEY;
const MODEL = process.env.GEMINI_MODEL || 'gemini-2-flash';

let genAI = null;

function getClient() {
    if (!API_KEY) {
        throw new Error(
            'GEMINI_API_KEY is not set. Please create a .env file with your Google AI Studio API key.'
        );
    }
    if (!genAI) {
        genAI = new GoogleGenerativeAI(API_KEY);
    }
    return genAI;
}

/**
 * Send preprocessed content to Gemini with a specialized system prompt.
 * Parses the JSON response and validates its structure.
 */
export async function analyzeWithGemini(systemInstruction, userContent) {
    const client = getClient();

    const model = client.getGenerativeModel({
        model: MODEL,
        systemInstruction,
        generationConfig: {
            responseMimeType: 'application/json',
            temperature: 0.2,
            maxOutputTokens: 4096,
        },
    });

    const result = await model.generateContent(userContent);
    const response = result.response;
    const text = response.text();

    // Parse and validate the JSON
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch {
        // If Gemini didn't return valid JSON, wrap the text response
        parsed = {
            risk_score: 0,
            risk_level: 'Unknown',
            summary: 'AI returned a non-JSON response. Raw output attached.',
            raw_output: text,
            key_findings: [],
        };
    }

    // Ensure required fields exist
    return {
        risk_score: parsed.risk_score ?? 0,
        risk_level: parsed.risk_level ?? 'Unknown',
        summary: parsed.summary ?? 'No summary available.',
        key_findings: Array.isArray(parsed.key_findings) ? parsed.key_findings : [],
        ...(parsed.raw_output ? { raw_output: parsed.raw_output } : {}),
    };
}
