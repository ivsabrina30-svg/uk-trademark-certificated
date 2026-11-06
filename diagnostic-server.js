/**
 * SSI TEAM - Live Vercel Remote & Local Deep Forensic Diagnostic Server v25.0
 * Target Website: https://uk-trademark-certificated.vercel.app/
 * Port: 9090 | Zero External Dependencies (Pure Node.js)
 * Run Command: node diagnostic-server.js
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const os = require('os');

const PORT = 9090;
const WORKSPACE_DIR = __dirname;
const DEFAULT_VERCEL_URL = 'https://uk-trademark-certificated.vercel.app/';

function getLocalLanIp() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '127.0.0.1';
}

// Fetch live HTML or JS content directly from Vercel URL (Follows Redirects)
function fetchRemoteTextContent(targetUrl, redirectCount = 0) {
    return new Promise((resolve) => {
        if (redirectCount > 5) {
            return resolve({ ok: false, statusCode: 0, error: 'Too many redirects', body: '' });
        }
        try {
            const client = targetUrl.startsWith('https') ? https : http;
            const req = client.get(targetUrl, {
                timeout: 8000,
                headers: {
                    'User-Agent': 'SSI-TEAM-Forensic-Diagnostic-Scanner/25.0',
                    'Cache-Control': 'no-cache'
                }
            }, (res) => {
                if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
                    const nextUrl = new URL(res.headers.location, targetUrl).toString();
                    return resolve(fetchRemoteTextContent(nextUrl, redirectCount + 1));
                }
                let rawData = '';
                res.setEncoding('utf8');
                res.on('data', (chunk) => { rawData += chunk; });
                res.on('end', () => {
                    resolve({
                        ok: res.statusCode >= 200 && res.statusCode < 400,
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: rawData
                    });
                });
            });
            req.on('error', (err) => resolve({ ok: false, statusCode: 0, error: err.message, body: '' }));
            req.on('timeout', () => {
                req.destroy();
                resolve({ ok: false, statusCode: 0, error: 'Connection Timeout', body: '' });
            });
        } catch (e) {
            resolve({ ok: false, statusCode: 0, error: e.message, body: '' });
        }
    });
}

function checkRemoteUrlStatus(targetUrl) {
    return new Promise((resolve) => {
        try {
            const client = targetUrl.startsWith('https') ? https : http;
            const req = client.request(targetUrl, { method: 'HEAD', timeout: 4500 }, (res) => {
                resolve({
                    ok: res.statusCode >= 200 && res.statusCode < 400,
                    statusCode: res.statusCode,
                    corsHeader: res.headers['access-control-allow-origin'] || null
                });
            });
            req.on('error', (err) => resolve({ ok: false, statusCode: 0, error: err.message }));
            req.on('timeout', () => {
                req.destroy();
                resolve({ ok: false, statusCode: 0, error: 'Timeout' });
            });
            req.end();
        } catch (e) {
            resolve({ ok: false, statusCode: 0, error: e.message });
        }
    });
}

async function performDeepAudit(targetSourceUrl, browserTelemetry = null) {
    const issues = [];
    const featureChecks = [];
    const targetUrl = targetSourceUrl || DEFAULT_VERCEL_URL;

    let rawContent = '';
    let scannedSourceLabel = targetUrl;
    let httpStatus = 200;

    // 1. Fetch Live Code Directly from Vercel Website
    const remoteRes = await fetchRemoteTextContent(targetUrl);
    if (remoteRes.ok && remoteRes.body) {
        rawContent = remoteRes.body;
        httpStatus = remoteRes.statusCode;
        featureChecks.push({
            feature: 'Live Vercel Website Reachability',
            status: 'PASS',
            detail: `${targetUrl} (HTTP ${httpStatus})`
        });
    } else {
        // Fallback to local index.html only if internet/Vercel is unreachable
        const fallbackLocal = path.join(WORKSPACE_DIR, 'index.html');
        if (fs.existsSync(fallbackLocal)) {
            rawContent = fs.readFileSync(fallbackLocal, 'utf8');
            scannedSourceLabel = `Local Fallback (index.html) - Vercel Error: ${remoteRes.error || remoteRes.statusCode}`;
            featureChecks.push({
                feature: 'Live Vercel Website Reachability',
                status: 'WARN',
                detail: `Vercel unreachable (${remoteRes.error || remoteRes.statusCode}), scanned local index.html`
            });
        } else {
            throw new Error(`লাইভ Vercel ওয়েবসাইট (${targetUrl}) থেকে ডাটা লোড করা যায়নি: ${remoteRes.error || 'HTTP ' + remoteRes.statusCode}`);
        }
    }

    const lines = rawContent.split(/\r?\n/);

    const addIssue = (line, severity, feature, issue, impact, fix, codeSnippet = null) => {
        const snippet = codeSnippet !== null
            ? codeSnippet
            : (typeof line === 'number' && lines[line - 1] ? lines[line - 1].trim().slice(0, 140) : '');
        issues.push({
            line,
            severity,
            feature,
            issue,
            impact,
            fix,
            codeSnippet: snippet
        });
    };

    // =========================================================================
    // LAYER 1: Character Encoding, DOCTYPE & Invisible Non-Breaking Space Audit
    // =========================================================================
    let doctypeCount = 0;
    const nbspLines = [];

    lines.forEach((lineText, idx) => {
        const ln = idx + 1;
        if (/<!DOCTYPE\s+html>/i.test(lineText)) {
            doctypeCount++;
            if (doctypeCount > 1) {
                addIssue(
                    ln,
                    'HIGH',
                    'HTML Document Structure',
                    `ডুপ্লিকেট <!DOCTYPE html> ডিক্লারেশন পাওয়া গেছে (লাইন ${ln})`,
                    'ব্রাউজার DOM পার্সিংয়ে বিভ্রান্তি তৈরি হতে পারে।',
                    `লাইন ${ln}-এর অতিরিক্ত <!DOCTYPE html> মুছে ফেলুন।`
                );
            }
        }
        if (/\u00A0/.test(lineText)) {
            nbspLines.push(ln);
        }
    });

    if (nbspLines.length > 0) {
        addIssue(
            nbspLines[0],
            'MEDIUM',
            'Source Formatting & Parser Safety',
            `কোডে মোট ${nbspLines.length}টি লাইনে অদৃশ্য Non-Breaking Space (\\u00A0) ক্যারেক্টার রয়েছে (শুরু লাইন: ${nbspLines.slice(0, 8).join(', ')})`,
            'জাভাস্ক্রিপ্ট পার্সার বা মিনিফায়ারে Unexpected Token SyntaxError তৈরি করতে পারে।',
            'কোড এডিটরে Find & Replace ব্যবহার করে \\u00A0 কে সাধারণ স্পেস দিয়ে রিপ্লেস করুন।'
        );
    }

    // =========================================================================
    // LAYER 2: Collect All HTML IDs & Detect Duplicate IDs with Exact Lines
    // =========================================================================
    const htmlIdMap = new Map();
    const idRegex = /\bid\s*=\s*["']([^"']+)["']/g;

    lines.forEach((lineText, idx) => {
        const ln = idx + 1;
        let match;
        while ((match = idRegex.exec(lineText)) !== null) {
            const idVal = match[1].trim();
            if (idVal.includes('${')) continue;
            if (!htmlIdMap.has(idVal)) {
                htmlIdMap.set(idVal, []);
            }
            htmlIdMap.get(idVal).push(ln);
        }
    });

    for (const [idVal, lineArr] of htmlIdMap.entries()) {
        if (lineArr.length > 1) {
            addIssue(
                lineArr[1],
                'CRITICAL',
                'DOM Element Identity',
                `ডুপ্লিকেট ID "${idVal}" একাধিকবার ব্যবহার করা হয়েছে (লাইন: ${lineArr.join(', ')})`,
                `document.getElementById('${idVal}') শুধুমাত্র প্রথম এলিমেন্টে কাজ করবে, বাকি ফিচারগুলো কাজ করবে না।`,
                `লাইন ${lineArr.join(' এবং ')}-এ "${idVal}" পরিবর্তন করে ইউনিক ID দিন।`
            );
        }
    }

    // =========================================================================
    // LAYER 3: Extract & Compile Every <script> Block (Including Remote Vercel Scripts)
    // =========================================================================
    const scriptBlocks = [];
    const scriptOpenRegex = /<script\b([^>]*)>/gi;
    let openMatch;

    while ((openMatch = scriptOpenRegex.exec(rawContent)) !== null) {
        const attrs = openMatch[1] || '';
        const openEndIdx = openMatch.index + openMatch[0].length;
        const closeIdx = rawContent.indexOf('</script>', openEndIdx);
        if (closeIdx === -1) {
            const unclosedLine = rawContent.slice(0, openMatch.index).split(/\r?\n/).length;
            addIssue(
                unclosedLine,
                'CRITICAL',
                'Script Tag Structure',
                `লাইন ${unclosedLine}-এ শুরু হওয়া <script> ট্যাগটি ক্লোজ (</script>) করা হয়নি!`,
                'পুরো অ্যাপ্লিকেশনের জাভাস্ক্রিপ্ট বন্ধ হয়ে যাবে।',
                `স্ক্রিপ্টের শেষে </script> যোগ করুন।`
            );
            break;
        }
        const startLine = rawContent.slice(0, openMatch.index).split(/\r?\n/).length;
        const jsCode = rawContent.slice(openEndIdx, closeIdx);
        scriptBlocks.push({ attrs, startLine, jsCode });
    }

    let combinedJsCode = '';
    for (let idx = 0; idx < scriptBlocks.length; idx++) {
        const block = scriptBlocks[idx];
        const srcMatch = block.attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
        if (srcMatch) {
            const srcUrl = srcMatch[1];
            // If relative script (e.g. firebase-config.js), fetch directly from live Vercel URL
            if (!/^https?:\/\//i.test(srcUrl) && !srcUrl.startsWith('//')) {
                const remoteScriptUrl = new URL(srcUrl, targetUrl).toString();
                const extRes = await fetchRemoteTextContent(remoteScriptUrl);
                if (!extRes.ok) {
                    addIssue(
                        block.startLine,
                        'MEDIUM',
                        'External Script Dependency',
                        `লাইভ সার্ভারে "${remoteScriptUrl}" ফাইলটি পাওয়া যায়নি (HTTP ${extRes.statusCode || extRes.error})`,
                        'Firebase ডাটাবেস কানেকশন কাজ করবে না এবং অ্যাপটি Offline LocalStorage মোডে চলবে।',
                        `Vercel ডিপ্লয়মেন্টে "${srcUrl}" ফাইলটি যুক্ত করুন।`
                    );
                } else {
                    try {
                        new vm.Script(extRes.body, { filename: remoteScriptUrl });
                        combinedJsCode += '\n' + extRes.body;
                        featureChecks.push({
                            feature: `Remote Script (${srcUrl})`,
                            status: 'PASS',
                            detail: `Loaded & Verified from ${remoteScriptUrl}`
                        });
                    } catch (extErr) {
                        addIssue(
                            block.startLine,
                            'CRITICAL',
                            `External Script (${srcUrl})`,
                            `"${remoteScriptUrl}" ফাইলে জাভাস্ক্রিপ্ট সিনট্যাক্স এরর: ${extErr.message}`,
                            `"${srcUrl}" লোড হওয়া মাত্রই ক্র্যাশ করবে।`,
                            `"${srcUrl}" ফাইলের সিনট্যাক্স ত্রুটি ঠিক করুন।`
                        );
                    }
                }
            }
            continue;
        }

        if (!block.jsCode.trim()) continue;
        combinedJsCode += '\n' + block.jsCode;

        try {
            new vm.Script(block.jsCode, {
                filename: `${scannedSourceLabel} (Script #${idx + 1})`,
                lineOffset: block.startLine - 1
            });
        } catch (syntaxErr) {
            const stackLines = (syntaxErr.stack || '').split('\n');
            const locMatch = stackLines[0] ? stackLines[0].match(/:(\d+)$/) : null;
            const exactLine = locMatch ? parseInt(locMatch[1], 10) : block.startLine;
            const codeLine = stackLines[1] ? stackLines[1].trim() : (lines[exactLine - 1] || '').trim();

            addIssue(
                exactLine,
                'CRITICAL',
                'JavaScript Compiler (vm.Script)',
                `জাভাস্ক্রিপ্ট সিনট্যাক্স এরর (লাইন ${exactLine}): ${syntaxErr.message}`,
                'এই স্ক্রিপ্ট ব্লকের সমস্ত বাটন এবং ফাংশন সম্পূর্ণ অকেজো হয়ে যাবে।',
                `লাইন ${exactLine}-এ "${codeLine}" অংশের ব্র্যাকেট, কোটেশন বা সিনট্যাক্স ঠিক করুন।`,
                codeLine
            );
        }
    }

    // =========================================================================
    // LAYER 4: Verify Every getElementById(...) Call Against Actual HTML IDs
    // =========================================================================
    const getByIdRegex = /document\.getElementById\(\s*["']([^"']+)["']\s*\)/g;
    lines.forEach((lineText, idx) => {
        const ln = idx + 1;
        let m;
        while ((m = getByIdRegex.exec(lineText)) !== null) {
            const targetId = m[1].trim();
            if (!htmlIdMap.has(targetId)) {
                addIssue(
                    ln,
                    'CRITICAL',
                    'DOM Data Binding Reference',
                    `জাভাস্ক্রিপ্টে document.getElementById('${targetId}') কল করা হয়েছে (লাইন ${ln}), কিন্তু HTML-এ id="${targetId}" নামের কোনো এলিমেন্ট নেই!`,
                    'এই লাইনটি রান করার সময় null রেফারেন্স বা "Cannot set properties of null" এরর তৈরি হবে।',
                    `HTML-এ id="${targetId}" যুক্ত করুন অথবা লাইন ${ln}-এ সঠিক ID ব্যবহার করুন।`
                );
            }
        }
    });

    // =========================================================================
    // LAYER 5: Verify Every HTML onclick / oninput / onchange / onsubmit Function
    // =========================================================================
    const definedFunctions = new Set([
        'alert', 'confirm', 'prompt', 'window', 'console', 'setTimeout', 'clearTimeout', 'decodeURIComponent', 'encodeURIComponent'
    ]);

    const fnDefRegex1 = /window\.([a-zA-Z0-9_$]+)\s*=/g;
    const fnDefRegex2 = /\bfunction\s+([a-zA-Z0-9_$]+)\s*\(/g;
    const fnDefRegex3 = /\b(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)/g;

    let fnMatch;
    while ((fnMatch = fnDefRegex1.exec(combinedJsCode)) !== null) definedFunctions.add(fnMatch[1]);
    while ((fnMatch = fnDefRegex2.exec(combinedJsCode)) !== null) definedFunctions.add(fnMatch[1]);
    while ((fnMatch = fnDefRegex3.exec(combinedJsCode)) !== null) definedFunctions.add(fnMatch[1]);

    const inlineHandlerRegex = /\bon(?:click|input|change|submit)\s*=\s*["']\s*(?:window\.)?([a-zA-Z0-9_$]+)\s*\(/g;
    lines.forEach((lineText, idx) => {
        const ln = idx + 1;
        let hm;
        while ((hm = inlineHandlerRegex.exec(lineText)) !== null) {
            const calledFn = hm[1];
            if (!definedFunctions.has(calledFn)) {
                addIssue(
                    ln,
                    'CRITICAL',
                    'UI Button / Event Handler',
                    `লাইন ${ln}-এ বাটন/ইনপুটে "${calledFn}()" ফাংশন কল করা হয়েছে, কিন্তু পুরো স্ক্রিপ্টে "${calledFn}" নামে কোনো ফাংশন ডিফাইন করা নেই!`,
                    `ইউজার এই বাটনে ক্লিক করলে "Uncaught ReferenceError: ${calledFn} is not defined" এরর হবে।`,
                    `স্ক্রিপ্টে window.${calledFn} = function() { ... } ডিফাইন করুন অথবা বাটনের ফাংশনের নাম ঠিক করুন।`
                );
            }
        }
    });

    // =========================================================================
    // LAYER 6: CSS, Google Fonts, Seal Image & Export Taint Audit
    // =========================================================================
    lines.forEach((lineText, idx) => {
        const ln = idx + 1;

        if (/fonts\.googleapis\.com\/css2\?family=Times\+New\+Roman/i.test(lineText)) {
            addIssue(
                ln,
                'MEDIUM',
                'CSS Font Loader',
                `লাইন ${ln}-এ Google Fonts থেকে "Times New Roman" ইমপোর্ট করা হয়েছে যা Google Fonts-এ নেই (HTTP 400 Error)।`,
                'প্রতিবার পেজ লোডের সময় ব্রাউজার কনসোলে নেটওয়ার্ক এরর দেখায়।',
                'এই @import লাইনটি মুছে ফেলুন অথবা "Tinos" ফন্ট ব্যবহার করুন।'
            );
        }

        if (/body\.eyecare\s*\{[^}]*filter\s*:/i.test(lineText)) {
            addIssue(
                ln,
                'HIGH',
                'CSS Layout & Fixed Modals',
                `লাইন ${ln}-এ body.eyecare-এ সরাসরি CSS filter ব্যবহার করা হয়েছে।`,
                'Warm Filter চালু করলে সব position: fixed মোডাল, সাইডবার এবং সার্টিফিকেট এক্সপোর্ট ভেঙে যাবে।',
                'body-তে filter না দিয়ে আলাদা #eyecareOverlay ডিভ ব্যবহার করুন।'
            );
        }

        if (/id=["']centralSealImg["'][^>]*crossorigin=["']anonymous["']/i.test(lineText)) {
            addIssue(
                ln,
                'CRITICAL',
                'Certificate Seal Image Loader',
                `লাইন ${ln}-এ #centralSealImg ট্যাগে crossorigin="anonymous" দেওয়া আছে যা exporya.b-cdn.net সার্ভার ব্লক করে দেয়।`,
                'আসল প্যাটেন্ট অফিস সিল লোড হতে পারে না এবং ফলব্যাক SVG বা খালি বক্স চলে আসে।',
                '#centralSealImg থেকে crossorigin="anonymous" সরিয়ে আসল লিংক সরাসরি রাখুন।'
            );
        }
    });

    // Check Seal Image URL status
    const sealUrlMatch = rawContent.match(/id=["']centralSealImg["'][^>]*src=["']([^"']+)["']/i);
    if (sealUrlMatch) {
        const sealUrl = sealUrlMatch[1];
        const sealCheck = await checkRemoteUrlStatus(sealUrl);
        featureChecks.push({
            feature: 'Original Patent Office Seal URL',
            status: sealCheck.ok ? 'PASS' : 'WARN',
            detail: `${sealUrl} (HTTP ${sealCheck.statusCode || sealCheck.error})`
        });
        if (!sealCheck.ok) {
            addIssue(
                'Network Asset',
                'HIGH',
                'Original Seal Image URL',
                `সার্টিফিকেট সিলের URL (${sealUrl}) রেসপন্স করছে না (Status: ${sealCheck.statusCode || sealCheck.error})`,
                'সার্টিফিকেটে সিল ইমেজ দেখা যাবে না।',
                'ইন্টারনেট কানেকশন বা সিলের ইমেজ লিংকটি পরীক্ষা করুন।'
            );
        }
    }

    // =========================================================================
    // LAYER 7: Security & XSS / Unhandled Firebase Async Audit
    // =========================================================================
    lines.forEach((lineText, idx) => {
        const ln = idx + 1;
        if (/onclick=["'][^"']*\$\{sanitizeInput\(/i.test(lineText)) {
            addIssue(
                ln,
                'HIGH',
                'Security / Inline Event Handler',
                `লাইন ${ln}-এ ইনলাইন onclick অ্যাট্রিবিউটের ভেতরে সরাসরি sanitizeInput() ব্যবহার করা হয়েছে।`,
                'ইমেইল বা স্ট্রিংয়ে সিঙ্গেল কোট (\') থাকলে HTML পার্সার সেটি ডিকোড করে JS SyntaxError ও XSS তৈরি করবে।',
                'ইনলাইন আর্গুমেন্টে encodeURIComponent() ও decodeURIComponent() ব্যবহার করুন।'
            );
        }
    });

    // =========================================================================
    // LAYER 8: Merge Live Browser DOM & Runtime Telemetry (If Sent via POST)
    // =========================================================================
    if (browserTelemetry && typeof browserTelemetry === 'object') {
        if (Array.isArray(browserTelemetry.runtimeErrors) && browserTelemetry.runtimeErrors.length > 0) {
            browserTelemetry.runtimeErrors.forEach((re) => {
                addIssue(
                    re.lineno || 'Runtime',
                    'CRITICAL',
                    'Live Browser Runtime Error',
                    `ব্রাউজারে লাইভ রানটাইম এরর ঘটেছে: ${re.message}`,
                    'সংশ্লিষ্ট ফিচারটি ক্লিক বা রান করার সময় ক্র্যাশ করেছে।',
                    `লাইন ${re.lineno || 'N/A'} পরীক্ষা করে এররটি সমাধান করুন।`
                );
            });
        }
        if (browserTelemetry.sealLoaded === false) {
            addIssue(
                '#centralSealImg',
                'HIGH',
                'Live Browser Seal Rendering',
                'ব্রাউজারে সার্টিফিকেট সিল ইমেজটি লোড হয়নি (naturalWidth === 0)।',
                'সার্টিফিকেটের উপরের প্যাটেন্ট অফিস সিল খালি দেখাচ্ছে।',
                '"Reload Original Seal" বাটনে ক্লিক করুন।'
            );
        }
        if (Array.isArray(browserTelemetry.unsyncedBindings) && browserTelemetry.unsyncedBindings.length > 0) {
            browserTelemetry.unsyncedBindings.forEach((ub) => {
                addIssue(
                    'DOM Sync',
                    'HIGH',
                    `Certificate Field (${ub.label})`,
                    `কন্ট্রোল প্যানেলের ইনপুটের সাথে সার্টিফিকেটের "${ub.label}" টেক্সট মিলছে না (${ub.detail})।`,
                    'সার্টিফিকেটে ভুল তথ্য প্রিন্ট বা ডাউনলোড হবে।',
                    '"অটো-সিঙ্ক ও রিপেয়ার" বাটনে ক্লিক করুন।'
                );
            });
        }
    }

    // Core Feature Matrix Verification
    const coreIds = [
        { id: 'authGatewayOverlay', name: 'Firebase Security Login Gateway' },
        { id: 'loginGatewayForm', name: 'Firebase Auth Login Form' },
        { id: 'unbanGatewayForm', name: 'Emergency Unban Key Form' },
        { id: 'inputTmNumber', name: 'TM Number Input' },
        { id: 'inputBrandName', name: 'Brand Name Input' },
        { id: 'inputProprietor', name: 'Proprietor Input' },
        { id: 'inputRegDate', name: 'Effective Date Input' },
        { id: 'inputEntryDate', name: 'Entry Date Input' },
        { id: 'inputSignature', name: 'Registrar Signature Input' },
        { id: 'centralSealImg', name: 'Patent Office Seal Image' },
        { id: 'certificateCanvasArea', name: 'A4 Certificate Canvas' },
        { id: 'userTableBody', name: 'IAM Subscribers Table' },
        { id: 'securityLogTableBody', name: 'Admin Security Logs Table' }
    ];

    coreIds.forEach(item => {
        const exists = htmlIdMap.has(item.id);
        featureChecks.push({
            feature: item.name,
            status: exists ? 'PASS' : 'WARN',
            line: exists ? htmlIdMap.get(item.id)[0] : null
        });
    });

    return {
        status: 'ok',
        serverIp: getLocalLanIp(),
        port: PORT,
        scannedFile: scannedSourceLabel,
        scannedFilePath: targetUrl,
        totalLines: lines.length,
        totalUniqueIds: htmlIdMap.size,
        totalFunctionsVerified: definedFunctions.size,
        totalIssues: issues.length,
        featureChecks,
        issues
    };
}

// Print Live Audit Report Directly in Laptop Terminal
function printTerminalReport(report) {
    console.log('\n------------------------------------------------------------------');
    console.log(`📡 LIVE VERCEL SCAN TARGET : ${report.scannedFile}`);
    console.log(`📊 TOTAL LINES SCANNED     : ${report.totalLines} lines`);
    console.log(`🆔 UNIQUE DOM IDs          : ${report.totalUniqueIds} IDs`);
    console.log(`⚙️  VERIFIED JS FUNCTIONS   : ${report.totalFunctionsVerified} functions`);
    console.log(`🚨 TOTAL ISSUES FOUND      : ${report.totalIssues}`);
    console.log('------------------------------------------------------------------');

    report.featureChecks.forEach(fc => {
        const icon = fc.status === 'PASS' ? '✅' : '⚠️';
        const lineInfo = fc.line ? ` (Line ${fc.line})` : (fc.detail ? ` [${fc.detail}]` : '');
        console.log(`${icon} ${fc.feature.padEnd(34)} : ${fc.status}${lineInfo}`);
    });

    if (report.issues.length > 0) {
        console.log('\n❌ DETECTED ISSUES ON LIVE VERCEL SITE:');
        report.issues.forEach((iss, i) => {
            console.log(`  [${i + 1}] (${iss.severity}) Line ${iss.line} - ${iss.feature}`);
            console.log(`      সমস্যা : ${iss.issue}`);
            console.log(`      সমাধান: ${iss.fix}`);
        });
    } else {
        console.log('\n🎉 ১০০% ক্লিন! আপনার লাইভ Vercel ওয়েবসাইটে কোনো সিনট্যাক্স বা DOM এরর নেই!');
    }
    console.log('==================================================================\n');
}

const server = http.createServer(async (req, res) => {
    // Full CORS & Private Network Access Headers so https://uk-trademark-certificated.vercel.app can connect to http://localhost:9090
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Private-Network', 'true');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (parsedUrl.pathname === '/proxy-seal') {
        const targetImgUrl = parsedUrl.searchParams.get('url') || 'https://exporya.b-cdn.net/wp-content/uploads/2024/02/exporya-trademark.jpg';
        const client = targetImgUrl.startsWith('https') ? https : http;
        client.get(targetImgUrl, (imgRes) => {
            res.writeHead(imgRes.statusCode || 200, {
                'Content-Type': imgRes.headers['content-type'] || 'image/jpeg',
                'Cache-Control': 'public, max-age=86400'
            });
            imgRes.pipe(res);
        }).on('error', (err) => {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        });
        return;
    }

    if (parsedUrl.pathname === '/scan') {
        let bodyData = '';
        req.on('data', chunk => { bodyData += chunk; });
        req.on('end', async () => {
            let browserTelemetry = null;
            if (bodyData) {
                try { browserTelemetry = JSON.parse(bodyData); } catch (e) {}
            }
            const requestedTargetUrl = parsedUrl.searchParams.get('url')
                || (browserTelemetry && browserTelemetry.siteUrl)
                || DEFAULT_VERCEL_URL;

            try {
                const report = await performDeepAudit(requestedTargetUrl, browserTelemetry);
                printTerminalReport(report);
                res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify(report, null, 2));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({ status: 'error', message: err.message }));
            }
        });
        return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
        service: 'SSI TEAM Live Vercel Diagnostic Bridge v25.0',
        targetVercelUrl: DEFAULT_VERCEL_URL,
        endpoints: ['/scan (GET/POST)', '/proxy-seal?url=...']
    }));
});

server.listen(PORT, '0.0.0.0', async () => {
    const lanIp = getLocalLanIp();
    console.log('==================================================================');
    console.log('🚀 SSI TEAM - LIVE VERCEL DIAGNOSTIC SERVER v25.0 RUNNING');
    console.log(`🌍 Target Vercel : ${DEFAULT_VERCEL_URL}`);
    console.log(`🔗 Local Bridge  : http://localhost:${PORT}/scan`);
    console.log(`🌐 Network URL   : http://${lanIp}:${PORT}/scan`);
    console.log('==================================================================');
    console.log('⏳ আপনার লাইভ Vercel ওয়েবসাইট স্ক্যান করা হচ্ছে...');

    try {
        const initialReport = await performDeepAudit(DEFAULT_VERCEL_URL);
        printTerminalReport(initialReport);
    } catch (err) {
        console.error('❌ প্রারম্ভিক Vercel স্ক্যানে ত্রুটি:', err.message);
    }
});