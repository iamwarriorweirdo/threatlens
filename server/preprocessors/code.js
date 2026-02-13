/**
 * Code Preprocessor
 * - Detects language hints
 * - Adds line numbers for easy reference
 * - Truncates to safe token limit
 */

const MAX_CHARS = 30000;

const LANGUAGE_HINTS = [
    { pattern: /\bimport\s+.*\s+from\s+['"]|require\s*\(|module\.exports|const\s+\w+\s*=\s*require/, name: 'JavaScript/Node.js' },
    { pattern: /\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import|print\s*\(/, name: 'Python' },
    { pattern: /<\?php|namespace\s+\w+|function\s+\w+\s*\(.*\)\s*{/, name: 'PHP' },
    { pattern: /\bpackage\s+\w+|func\s+\w+\s*\(|import\s+\"/, name: 'Go' },
    { pattern: /\bpublic\s+(static\s+)?class\s+|System\.out\.print/, name: 'Java' },
    { pattern: /\busing\s+System|namespace\s+\w+\s*{|Console\.Write/, name: 'C#' },
    { pattern: /\b#include\s*<|int\s+main\s*\(|printf\s*\(|std::/, name: 'C/C++' },
    { pattern: /<script|<\/div>|document\.getElementById|addEventListener/, name: 'HTML/JavaScript' },
    { pattern: /\$\w+\s*=|#!/, name: 'Shell/Bash' },
    { pattern: /powershell|Get-ChildItem|Set-ExecutionPolicy|Invoke-WebRequest/, name: 'PowerShell' },
];

function detectLanguage(code) {
    for (const { pattern, name } of LANGUAGE_HINTS) {
        if (pattern.test(code)) return name;
    }
    return 'Unknown';
}

function addLineNumbers(code) {
    const lines = code.split('\n');
    const pad = String(lines.length).length;
    return lines
        .map((line, i) => `${String(i + 1).padStart(pad, ' ')} | ${line}`)
        .join('\n');
}

export async function preprocessCode(rawCode) {
    const truncated = rawCode.length > MAX_CHARS
        ? rawCode.substring(0, MAX_CHARS) + '\n\n[... TRUNCATED — original code exceeds 30K characters ...]'
        : rawCode;

    const language = detectLanguage(truncated);
    const numbered = addLineNumbers(truncated);

    return `## Code Analysis Request

**Detected Language:** ${language}
**Total Characters:** ${rawCode.length}
${rawCode.length > MAX_CHARS ? `**Note:** Code was truncated from ${rawCode.length} to ${MAX_CHARS} characters.\n` : ''}
**Source Code:**
\`\`\`
${numbered}
\`\`\`

Analyze this code for malicious intent, backdoors, obfuscation, and security vulnerabilities.`;
}
