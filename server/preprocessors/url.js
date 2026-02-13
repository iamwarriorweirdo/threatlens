/**
 * URL Preprocessor
 * - Parses URL structure (subdomains, TLD, path, params)
 * - Detects homograph characters (Cyrillic/Latin lookalikes)
 * - Performs DNS lookup
 * - Attempts to follow redirects for short URLs
 */

import dns from 'dns/promises';

// Cyrillic characters that look like Latin characters
const HOMOGRAPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
    'х': 'x', 'у': 'y', 'А': 'A', 'В': 'B', 'С': 'C',
    'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M', 'О': 'O',
    'Р': 'P', 'Т': 'T', 'Х': 'X', 'і': 'i', 'ј': 'j',
    'ё': 'ë', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ʜ': 'h',
};

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.club', '.work', '.click', '.link', '.info'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'v.gd', 'buff.ly', 'rebrand.ly', 'short.io'];
const BRAND_TARGETS = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 'instagram', 'github', 'netflix', 'linkedin', 'twitter', 'bank', 'login', 'verify', 'secure', 'account', 'update', 'confirm'];

function detectHomographs(domain) {
    const found = [];
    for (const char of domain) {
        if (HOMOGRAPH_MAP[char]) {
            found.push({ char, lookalike: HOMOGRAPH_MAP[char], codepoint: `U+${char.codePointAt(0).toString(16).toUpperCase()}` });
        }
    }
    return found;
}

function analyzeUrlStructure(urlString) {
    let parsed;
    try {
        // Add protocol if missing
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
            urlString = 'http://' + urlString;
        }
        parsed = new URL(urlString);
    } catch {
        return { error: `Invalid URL: "${urlString}"` };
    }

    const hostname = parsed.hostname;
    const parts = hostname.split('.');
    const tld = '.' + parts[parts.length - 1];
    const subdomainCount = parts.length - 2; // domain.tld = 0 subdomains

    return {
        fullUrl: parsed.href,
        protocol: parsed.protocol,
        hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
        path: parsed.pathname,
        queryParams: parsed.search,
        hash: parsed.hash,
        tld,
        subdomainCount,
        subdomains: parts.slice(0, -2).join('.'),
        isSuspiciousTld: SUSPICIOUS_TLDS.includes(tld.toLowerCase()),
        isIpAddress: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname),
        isShortener: URL_SHORTENERS.some(s => hostname.includes(s)),
        brandTargets: BRAND_TARGETS.filter(b => hostname.toLowerCase().includes(b) || parsed.pathname.toLowerCase().includes(b)),
    };
}

async function dnsLookup(hostname) {
    try {
        const [aRecords, mxRecords] = await Promise.allSettled([
            dns.resolve4(hostname),
            dns.resolveMx(hostname),
        ]);
        return {
            a_records: aRecords.status === 'fulfilled' ? aRecords.value : [],
            mx_records: mxRecords.status === 'fulfilled' ? mxRecords.value.map(r => r.exchange) : [],
        };
    } catch {
        return { a_records: [], mx_records: [], error: 'DNS lookup failed' };
    }
}

async function followRedirects(urlString) {
    try {
        if (!urlString.startsWith('http')) urlString = 'http://' + urlString;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        const res = await fetch(urlString, {
            method: 'HEAD',
            redirect: 'manual',
            signal: controller.signal,
            headers: { 'User-Agent': 'ThreatLens Security Scanner/1.0' },
        });
        clearTimeout(timeout);

        if (res.status >= 300 && res.status < 400) {
            const location = res.headers.get('location');
            return { redirectsTo: location, statusCode: res.status };
        }
        return { redirectsTo: null, statusCode: res.status };
    } catch (err) {
        return { redirectsTo: null, error: `Could not follow URL: ${err.message}` };
    }
}

export async function preprocessUrl(urlInput) {
    const trimmed = urlInput.trim();
    const sections = [];

    sections.push(`## URL Analysis Request\n\n**Input URL:** \`${trimmed}\``);

    // 1. URL Structure Analysis
    const structure = analyzeUrlStructure(trimmed);
    if (structure.error) {
        sections.push(`### URL Structure\n⚠️ ${structure.error}`);
        return sections.join('\n\n');
    }

    sections.push(`### URL Structure
- **Full URL:** ${structure.fullUrl}
- **Protocol:** ${structure.protocol}
- **Hostname:** ${structure.hostname}
- **Port:** ${structure.port}
- **Path:** ${structure.path}
- **Query Params:** ${structure.queryParams || 'None'}
- **TLD:** ${structure.tld} ${structure.isSuspiciousTld ? '⚠️ SUSPICIOUS TLD' : ''}
- **Subdomain Count:** ${structure.subdomainCount} ${structure.subdomainCount > 3 ? '⚠️ EXCESSIVE SUBDOMAINS' : ''}
- **Is IP Address:** ${structure.isIpAddress ? '⚠️ YES' : 'No'}
- **Is URL Shortener:** ${structure.isShortener ? '⚠️ YES' : 'No'}
- **Brand Targets Detected:** ${structure.brandTargets.length > 0 ? '⚠️ ' + structure.brandTargets.join(', ') : 'None'}`);

    // 2. Homograph Detection
    const homographs = detectHomographs(structure.hostname);
    if (homographs.length > 0) {
        const details = homographs.map(h => `  - Character "${h.char}" (${h.codepoint}) looks like Latin "${h.lookalike}"`).join('\n');
        sections.push(`### ⚠️ Homograph Characters Detected
${details}`);
    } else {
        sections.push(`### Homograph Check\n✅ No homograph characters detected.`);
    }

    // 3. DNS Lookup
    const dnsData = await dnsLookup(structure.hostname);
    sections.push(`### DNS Records
- **A Records:** ${dnsData.a_records.length > 0 ? dnsData.a_records.join(', ') : 'None / Failed'}
- **MX Records:** ${dnsData.mx_records.length > 0 ? dnsData.mx_records.join(', ') : 'None / Failed'}
${dnsData.error ? `- **Error:** ${dnsData.error}` : ''}`);

    // 4. Redirect chain (for short URLs)
    if (structure.isShortener) {
        const redirect = await followRedirects(trimmed);
        if (redirect.redirectsTo) {
            sections.push(`### Redirect Chain
- **Short URL redirects to:** ${redirect.redirectsTo}
- **HTTP Status:** ${redirect.statusCode}`);
        } else {
            sections.push(`### Redirect Chain
- **Note:** ${redirect.error || 'No redirect detected'}`);
        }
    }

    sections.push(`\nAnalyze this URL for phishing attempts, homograph attacks, malware delivery, and deceptive intent.`);

    return sections.join('\n\n');
}
