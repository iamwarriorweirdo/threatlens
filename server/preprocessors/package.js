/**
 * Package Preprocessor
 * - Fetches real metadata from npm registry
 * - Extracts security-relevant fields: scripts, author, creation date, dependencies
 * - Formats a structured context for the AI
 */

const NPM_REGISTRY = 'https://registry.npmjs.org';

export async function preprocessPackage(packageInput) {
    // The input might be just a name like "colors-lib-v2"
    // or it could be a JSON string with package.json content
    const trimmed = packageInput.trim();

    // Try to detect if it's a package name or raw JSON
    let packageName = trimmed;
    let providedManifest = null;

    if (trimmed.startsWith('{')) {
        try {
            providedManifest = JSON.parse(trimmed);
            packageName = providedManifest.name || 'unknown';
        } catch {
            // Not valid JSON, treat as package name
        }
    }

    // Fetch metadata from npm registry
    let registryData = null;
    let registryError = null;

    try {
        const res = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(packageName)}`);
        if (res.ok) {
            registryData = await res.json();
        } else if (res.status === 404) {
            registryError = `Package "${packageName}" not found in npm registry.`;
        } else {
            registryError = `NPM Registry returned HTTP ${res.status}`;
        }
    } catch (err) {
        registryError = `Failed to fetch from npm registry: ${err.message}`;
    }

    // Build analysis context
    const sections = [];
    sections.push(`## Package Analysis Request\n\n**Package Name:** ${packageName}`);

    if (registryData) {
        const latest = registryData['dist-tags']?.latest;
        const latestVersion = latest ? registryData.versions?.[latest] : null;
        const timeData = registryData.time || {};
        const created = timeData.created;
        const modified = timeData.modified;

        // Author info
        const author = registryData.author
            ? (typeof registryData.author === 'string' ? registryData.author : `${registryData.author.name || 'Unknown'} <${registryData.author.email || 'no email'}>`)
            : 'No author listed';

        // Maintainers
        const maintainers = registryData.maintainers?.map(m => m.name).join(', ') || 'None listed';

        sections.push(`### Registry Metadata
- **Latest Version:** ${latest || 'N/A'}
- **Author:** ${author}
- **Maintainers:** ${maintainers}
- **Created:** ${created || 'N/A'}
- **Last Modified:** ${modified || 'N/A'}
- **Total Versions:** ${Object.keys(registryData.versions || {}).length}
- **License:** ${registryData.license || 'None specified'}
- **Description:** ${registryData.description || 'No description'}`);

        // Scripts (critical for security)
        if (latestVersion?.scripts) {
            const scripts = latestVersion.scripts;
            const suspiciousKeys = ['preinstall', 'postinstall', 'preuninstall', 'postuninstall', 'prepare', 'prepublish'];
            const relevantScripts = {};
            for (const key of Object.keys(scripts)) {
                if (suspiciousKeys.includes(key) || scripts[key].includes('curl') || scripts[key].includes('wget') || scripts[key].includes('eval') || scripts[key].includes('base64')) {
                    relevantScripts[key] = scripts[key];
                }
            }
            if (Object.keys(relevantScripts).length > 0) {
                sections.push(`### ⚠️ Install/Lifecycle Scripts (Security-Critical)
\`\`\`json
${JSON.stringify(relevantScripts, null, 2)}
\`\`\``);
            }

            // Also show all scripts for context
            sections.push(`### All Scripts
\`\`\`json
${JSON.stringify(scripts, null, 2)}
\`\`\``);
        }

        // Dependencies
        if (latestVersion?.dependencies && Object.keys(latestVersion.dependencies).length > 0) {
            sections.push(`### Dependencies
\`\`\`json
${JSON.stringify(latestVersion.dependencies, null, 2)}
\`\`\``);
        }

    } else {
        sections.push(`### Registry Lookup
⚠️ ${registryError}`);
    }

    // If the user also provided raw package.json content
    if (providedManifest) {
        sections.push(`### User-Provided package.json
\`\`\`json
${JSON.stringify(providedManifest, null, 2)}
\`\`\``);
    }

    sections.push(`\nAnalyze this package for supply chain security risks, typosquatting, malicious scripts, and suspicious behavior.`);

    return sections.join('\n\n');
}
