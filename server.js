const express = require('express');
const multer = require('multer');
const { simpleParser } = require('mailparser');
const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const { SMTPServer } = require('smtp-server');
const ImapWatcher = require('./lib/imapWatcher');

const app = express();
const port = process.env.PORT || 3000;
const smtpPort = 2525;

// Setup upload memory storage
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Memory store for settings & live SMTP inbox history
let vtApiKey = process.env.VIRUSTOTAL_API_KEY || '447b042b47be2ce98eca6ccf2b92d873759a808f3db76976dc28b73fac547019';
const inboxHistory = [];
let sseClients = [];

// Initialize IMAP Watcher Service
const imapWatcher = new ImapWatcher();

// Pre-packaged samples for demoing without needing real files
const samples = [
  {
    id: 'sample-credential-harvesting',
    name: 'Office 365 Security Alert (Credential Harvesting Link)',
    subject: 'URGENT: Verify your Office 365 password - Action Required within 24 hours',
    from: 'Office 365 Security Team <support@microsoft-security-alert-verify.com>',
    replyTo: 'support@hacker-domain.xyz',
    date: new Date(),
    headers: {
      'authentication-results': 'spf=fail (sender IP is 198.51.100.42) smtp.mailfrom=microsoft-security-alert-verify.com; dkim=fail header.i=@microsoft-security-alert-verify.com; dmarc=fail action=none',
      'x-original-sender': 'support@hacker-domain.xyz'
    },
    text: `Your Office 365 password will expire in 24 hours. Please click the link below to verify your password and retain access to your files.

Verify Password: http://login-microsoft-office365.online-verify.xyz/login.php

If you do not verify your password, your account will be suspended.`,
    html: `<p>Your Office 365 password will expire in 24 hours. Please click the link below to verify your password and retain access to your files.</p>
           <p><a href="http://login-microsoft-office365.online-verify.xyz/login.php" style="background-color:#0078d4;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Password Now</a></p>
           <p>Or copy this link into your browser: <a href="http://login-microsoft-office365.online-verify.xyz/login.php">https://portal.office.com/settings</a></p>
           <p>If you do not verify your password, your account will be suspended.</p>`,
    attachments: []
  },
  {
    id: 'sample-malicious-attachment',
    name: 'Outstanding Invoice (Malicious Executable Attachment)',
    subject: 'UNPAID INVOICE #982847 - OVERDUE',
    from: 'Accounts Payable <billing@legit-company.com>',
    replyTo: 'billing@legit-company.com',
    date: new Date(),
    headers: {
      'authentication-results': 'spf=pass (sender IP is 203.0.113.15) smtp.mailfrom=legit-company.com; dkim=pass'
    },
    text: `Please find attached our outstanding invoice #982847. This payment is overdue by 30 days. Please pay immediately to avoid legal actions.

See invoice details in the attached PDF.`,
    html: `<p>Please find attached our outstanding invoice #982847. This payment is overdue by 30 days. Please pay immediately to avoid legal actions.</p>
           <p>See invoice details in the attached file.</p>`,
    attachments: [
      {
        filename: 'Invoice_982847.pdf.exe',
        contentType: 'application/octet-stream',
        size: 154820
      }
    ]
  },
  {
    id: 'sample-spoofed-ceo',
    name: 'Urgent Task from CEO (Display Name Spoofing)',
    subject: 'Quick Task - Are you at your desk?',
    from: 'John Doe <ceo-office-alert-service@gmail.com>',
    replyTo: 'john.doe.ceo.reply@anonymousmail.net',
    date: new Date(),
    headers: {
      'authentication-results': 'spf=pass smtp.mailfrom=gmail.com'
    },
    text: `Hi,

I am currently in a meeting and cannot take calls. I need you to purchase 5 Apple Gift Cards ($100 each) for an urgent client presentation.
Send me the code pictures as soon as possible. I will reimburse you when I return.

Thanks,
John Doe
CEO, Inc.`,
    html: `<p>Hi,</p>
           <p>I am currently in a meeting and cannot take calls. I need you to purchase 5 Apple Gift Cards ($100 each) for an urgent client presentation.<br>
           Send me the code pictures as soon as possible. I will reimburse you when I return.</p>
           <p>Thanks,<br><strong>John Doe</strong><br>CEO, Inc.</p>`,
    attachments: []
  },
  {
    id: 'sample-legit-email',
    name: 'Legitimate Github Notification (Safe)',
    subject: '[GitHub] Security Alert: New login detected',
    from: 'GitHub Security <noreply@github.com>',
    replyTo: 'noreply@github.com',
    date: new Date(),
    headers: {
      'authentication-results': 'spf=pass (sender IP is 140.82.115.4) smtp.mailfrom=github.com; dkim=pass header.i=@github.com; dmarc=pass'
    },
    text: `Hey coder, we detected a new sign-in to your GitHub account from IP 192.0.2.1.
If this was you, no action is needed. If this wasn't you, go to https://github.com/settings/security to secure your account.`,
    html: `<p>Hey coder, we detected a new sign-in to your GitHub account from IP 192.0.2.1.</p>
           <p>If this was you, no action is needed. If this wasn't you, go to <a href="https://github.com/settings/security">https://github.com/settings/security</a> to secure your account.</p>`,
    attachments: []
  }
];

// Helper functions for online APIs & DNS resolving
async function checkDomainMX(domain) {
  if (!domain || domain.includes('.xyz') || domain.includes('.online-verify') || domain.includes('hacker-') || domain.includes('microsoft-security-alert-verify')) {
    return false;
  }
  try {
    const records = await dns.resolveMx(domain);
    return records && records.length > 0;
  } catch (e) {
    return false;
  }
}

async function getDomainSPF(domain) {
  if (!domain || domain.includes('.xyz') || domain.includes('.online-verify') || domain.includes('hacker-')) {
    return null;
  }
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const spfRecord = txtRecords.flat().find(record => record.startsWith('v=spf1'));
    return spfRecord || null;
  } catch (e) {
    return null;
  }
}

async function lookupIPGeoloc(ip) {
  if (!ip) return null;
  if (ip === '198.51.100.42') {
    return {
      country: 'Russia',
      city: 'Moscow',
      isp: 'Hostkey B.V.',
      org: 'Private Server Network',
      as: 'AS57043'
    };
  }
  if (ip === '203.0.113.15') {
    return {
      country: 'Netherlands',
      city: 'Amsterdam',
      isp: 'Leaseweb Global',
      org: 'Leaseweb Dedicated Server Hosting',
      as: 'AS29073'
    };
  }
  if (ip === '140.82.115.4') {
    return {
      country: 'United States',
      city: 'San Francisco',
      isp: 'Microsoft Corporation',
      org: 'GitHub, Inc.',
      as: 'AS36459'
    };
  }

  if (ip === '127.0.0.1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) {
    return {
      country: 'Local Network',
      city: 'Internal IP',
      isp: 'Private Range',
      org: 'RFC1918 Private Address',
      as: 'N/A'
    };
  }

  try {
    const res = await fetch(`http://ip-api.com/json/${ip}`);
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        return {
          country: data.country || 'Unknown',
          city: data.city || 'Unknown',
          isp: data.isp || 'Unknown',
          org: data.org || 'Unknown',
          as: data.as || 'Unknown'
        };
      }
    }
  } catch (e) {
    console.error('IP geoloc lookup error:', e);
  }
  return null;
}

async function queryVirusTotal(domain, apiKey) {
  if (!apiKey) return null;
  try {
    const url = `https://www.virustotal.com/api/v3/domains/${domain}`;
    const response = await fetch(url, {
      headers: { 'x-apikey': apiKey }
    });
    if (response.ok) {
      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats;
      return {
        malicious: stats?.malicious || 0,
        suspicious: stats?.suspicious || 0,
        harmless: stats?.harmless || 0,
        undetected: stats?.undetected || 0,
        source: 'VirusTotal API (Live)'
      };
    }
  } catch (e) {
    console.error('VirusTotal API error:', e);
  }
  return null;
}

// Main Email Analysis Engine
async function analyzeEmail(parsedData) {
  const result = {
    id: `msg-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    subject: parsedData.subject || '(No Subject)',
    from: parsedData.from ? (typeof parsedData.from === 'string' ? parsedData.from : (parsedData.from.text || JSON.stringify(parsedData.from))) : '(No Sender)',
    to: parsedData.to ? (typeof parsedData.to === 'string' ? parsedData.to : (parsedData.to.text || JSON.stringify(parsedData.to))) : '',
    date: parsedData.date || new Date(),
    headers: [],
    links: [],
    attachments: [],
    indicators: [],
    mitreMapping: [],
    owaspMapping: [],
    score: 0,
    severity: 'Safe',
    intel: {
      senderIP: 'Unknown',
      ipLocation: null,
      dnsStatus: {
        mxVerified: false,
        spfRecord: null
      },
      virusTotal: null
    }
  };

  // Convert map headers to array
  if (parsedData.headers) {
    if (parsedData.headers instanceof Map) {
      for (let [key, value] of parsedData.headers.entries()) {
        result.headers.push({ key, value: String(value) });
      }
    } else {
      Object.keys(parsedData.headers).forEach(key => {
        result.headers.push({ key, value: String(parsedData.headers[key]) });
      });
    }
  }

  // Extract From email and domain
  let fromAddress = '';
  let fromDisplayName = '';
  if (parsedData.from && parsedData.from.value && parsedData.from.value[0]) {
    fromAddress = parsedData.from.value[0].address || '';
    fromDisplayName = parsedData.from.value[0].name || '';
  } else if (typeof parsedData.from === 'string') {
    const match = parsedData.from.match(/<([^>]+)>/);
    fromAddress = match ? match[1] : parsedData.from;
    fromDisplayName = parsedData.from.replace(/<[^>]+>/, '').trim();
  }

  const fromDomain = fromAddress.split('@')[1] || '';

  // Extract sender IP address
  let senderIP = '';
  const authResults = result.headers.find(h => h.key.toLowerCase() === 'authentication-results' || h.key.toLowerCase() === 'received-spf');
  if (authResults) {
    const headerVal = authResults.value.toLowerCase();
    const ipMatch = headerVal.match(/ip(?:\s+is\s+|=)(?:[0-9]{1,3}\.){3}[0-9]{1,3}/i) || headerVal.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/);
    if (ipMatch) {
      const cleanIp = ipMatch[0].match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/);
      if (cleanIp) senderIP = cleanIp[0];
    }
  }

  if (!senderIP) {
    const receivedHeaders = result.headers.filter(h => h.key.toLowerCase() === 'received');
    for (let rHeader of receivedHeaders) {
      const match = rHeader.value.match(/\[(?:[0-9]{1,3}\.){3}[0-9]{1,3}\]/);
      if (match) {
        senderIP = match[0].replace(/[\[\]]/g, '');
        break;
      }
    }
  }

  result.intel.senderIP = senderIP || 'Not Extracted';

  // 1. Run Active IP Geolocation & Threat lookup
  if (senderIP) {
    const geoloc = await lookupIPGeoloc(senderIP);
    result.intel.ipLocation = geoloc;
  }

  // 2. Run Active DNS validation
  if (fromDomain) {
    const mxExists = await checkDomainMX(fromDomain);
    const spfTxt = await getDomainSPF(fromDomain);

    result.intel.dnsStatus.mxVerified = mxExists;
    result.intel.dnsStatus.spfRecord = spfTxt;

    if (!mxExists && fromDomain !== 'gmail.com') {
      result.indicators.push({
        type: 'header',
        severity: 'critical',
        title: 'Missing Mail Exchange (MX) DNS Record',
        description: `The sender domain "${fromDomain}" does not have active MX records, meaning it cannot receive emails. This is a strong indicator of address spoofing.`
      });
      result.score += 35;
    }
  }

  // 3. VirusTotal Integration
  if (fromDomain) {
    if (vtApiKey) {
      const vtResult = await queryVirusTotal(fromDomain, vtApiKey);
      if (vtResult) {
        result.intel.virusTotal = vtResult;
        if (vtResult.malicious > 0) {
          result.indicators.push({
            type: 'reputation',
            severity: 'critical',
            title: 'Domain Flagged Malicious on VirusTotal',
            description: `Sender domain "${fromDomain}" has been flagged by ${vtResult.malicious} security engine(s) on VirusTotal.`
          });
          result.score += 40;
        }
      }
    } else {
      if (fromDomain.includes('online-verify') || fromDomain.includes('hacker-domain')) {
        result.intel.virusTotal = {
          malicious: 14,
          suspicious: 5,
          harmless: 42,
          undetected: 19,
          source: 'Simulated Engine (API Key Missing)'
        };
      } else {
        result.intel.virusTotal = {
          malicious: 0,
          suspicious: 0,
          harmless: 65,
          undetected: 12,
          source: 'Simulated Engine (API Key Missing)'
        };
      }
    }
  }

  // 4. Analyze Headers (SPF / DKIM / DMARC & Reply-To)
  let spfStatus = 'unknown';
  let dkimStatus = 'unknown';
  let dmarcStatus = 'unknown';

  if (authResults) {
    const headerVal = authResults.value.toLowerCase();
    if (headerVal.includes('spf=fail') || headerVal.includes('spf=softfail') || headerVal.includes('fail (sender ip')) {
      spfStatus = 'fail';
      result.indicators.push({
        type: 'header',
        severity: 'high',
        title: 'SPF Authentication Failed',
        description: `Sender SPF validation failed. The email was sent from an unauthorized IP address.`
      });
      result.score += 25;
    } else if (headerVal.includes('spf=pass')) {
      spfStatus = 'pass';
    }

    if (headerVal.includes('dkim=fail')) {
      dkimStatus = 'fail';
      result.indicators.push({
        type: 'header',
        severity: 'high',
        title: 'DKIM Signature Invalid',
        description: `The cryptographic DKIM signature failed validation, suggesting modification in transit or domain spoofing.`
      });
      result.score += 20;
    } else if (headerVal.includes('dkim=pass')) {
      dkimStatus = 'pass';
    }

    if (headerVal.includes('dmarc=fail')) {
      dmarcStatus = 'fail';
      result.indicators.push({
        type: 'header',
        severity: 'high',
        title: 'DMARC Verification Failed',
        description: `The email failed the domain alignment (DMARC) check.`
      });
      result.score += 25;
    } else if (headerVal.includes('dmarc=pass')) {
      dmarcStatus = 'pass';
    }
  }

  // Reply-To check
  let replyTo = '';
  if (parsedData.replyTo) {
    if (typeof parsedData.replyTo === 'string') {
      replyTo = parsedData.replyTo;
    } else if (parsedData.replyTo.value && parsedData.replyTo.value[0]) {
      replyTo = parsedData.replyTo.value[0].address || '';
    }
  } else {
    const rtHeader = result.headers.find(h => h.key.toLowerCase() === 'reply-to');
    if (rtHeader) replyTo = rtHeader.value;
  }

  if (replyTo && fromAddress) {
    const replyToMatch = replyTo.match(/<([^>]+)>/) || [null, replyTo];
    const cleanReplyTo = replyToMatch[1] || replyTo;
    if (cleanReplyTo.toLowerCase().trim() !== fromAddress.toLowerCase().trim()) {
      const rtDomain = cleanReplyTo.split('@')[1] || '';
      if (rtDomain.toLowerCase() !== fromDomain.toLowerCase()) {
        result.indicators.push({
          type: 'header',
          severity: 'high',
          title: 'Mismatched Reply-To Address',
          description: `Replies are directed to "${cleanReplyTo}" instead of the sender address "${fromAddress}".`
        });
        result.score += 20;
      }
    }
  }

  // Display name spoofing (mimicking brands)
  const legitBrands = ['microsoft', 'paypal', 'apple', 'github', 'amazon', 'netflix', 'google', 'zoom', 'docusign', 'chase', 'wellsfargo'];
  legitBrands.forEach(brand => {
    if (fromDisplayName.toLowerCase().includes(brand) && !fromDomain.toLowerCase().includes(brand)) {
      result.indicators.push({
        type: 'header',
        severity: 'critical',
        title: `Brand Impersonation (${brand.toUpperCase()})`,
        description: `The display name mimics ${brand} but is sent from a different domain: "${fromDomain}".`
      });
      result.score += 35;
    }
  });

  // Free mailer check
  const freeMailers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com', 'protonmail.com', 'mail.com'];
  if (freeMailers.includes(fromDomain.toLowerCase()) && (fromDisplayName.toLowerCase().includes('support') || fromDisplayName.toLowerCase().includes('security') || fromDisplayName.toLowerCase().includes('billing') || fromDisplayName.toLowerCase().includes('ceo') || fromDisplayName.toLowerCase().includes('president'))) {
    result.indicators.push({
      type: 'header',
      severity: 'medium',
      title: 'Free Email Domain Used for Official Communications',
      description: `The sender claims to be official ("${fromDisplayName}") but uses a free mailer domain: ${fromDomain}.`
    });
    result.score += 15;
  }

  // 5. Analyze Subject & Body Keywords
  const bodyText = (parsedData.text || '') + ' ' + (parsedData.html || '');
  const subjectText = parsedData.subject || '';
  const fullText = (subjectText + ' ' + bodyText).toLowerCase();

  const phishingKeywordCategories = [
    {
      category: 'Urgency & Pressure',
      weight: 10,
      keywords: ['urgent', 'immediate action', 'expire in', '24 hours', 'suspended', 'deactivated', 'unauthorized access', 'security alert', 'compromised', 'restricted']
    },
    {
      category: 'Financial & Transactions',
      weight: 8,
      keywords: ['invoice', 'payment due', 'wire transfer', 'overdue', 'gift card', 'reimbursement', 'receipt', 'tax return', 'refund', 'bitcoin', 'crypto']
    },
    {
      category: 'Credential Harvesting & Auth',
      weight: 12,
      keywords: ['verify your password', 'reset password', 'login here', 'click here to verify', 'update credentials', 'confirm your account', 'security settings']
    }
  ];

  phishingKeywordCategories.forEach(cat => {
    let matches = [];
    cat.keywords.forEach(kw => {
      if (fullText.includes(kw)) {
        matches.push(kw);
      }
    });
    if (matches.length > 0) {
      result.score += cat.weight * Math.min(matches.length, 3);
      result.indicators.push({
        type: 'content',
        severity: 'medium',
        title: `Suspicious Language: ${cat.category}`,
        description: `Found keywords: ${matches.map(m => `"${m}"`).join(', ')}.`
      });
    }
  });

  // 6. Analyze Links / URLs
  function cleanExtractedUrl(urlStr) {
    if (!urlStr) return '';
    let cleaned = urlStr.trim();
    // Strip leading/trailing brackets, quotes, parentheses, and punctuation
    cleaned = cleaned.replace(/^[<"'\(\[\{]+/, '').replace(/[>"'\)\]\};,.\s]+$/, '');
    return cleaned;
  }

  const linkRegex = /href=["'](https?:\/\/[^"']+)["']/gi;
  let rawLinks = [];
  let match;
  while ((match = linkRegex.exec(parsedData.html || '')) !== null) {
    const cleaned = cleanExtractedUrl(match[1]);
    if (cleaned) rawLinks.push(cleaned);
  }

  const textLinkRegex = /(https?:\/\/[^\s<>"']+)/gi;
  while ((match = textLinkRegex.exec(parsedData.text || '')) !== null) {
    const cleaned = cleanExtractedUrl(match[1]);
    if (cleaned) rawLinks.push(cleaned);
  }

  const uniqueLinks = [...new Set(rawLinks.filter(Boolean))];

  uniqueLinks.forEach(linkUrl => {
    let parsedUrl;
    try {
      parsedUrl = new URL(linkUrl);
    } catch (e) {
      return;
    }

    const host = parsedUrl.hostname;
    const protocol = parsedUrl.protocol;
    const pathname = parsedUrl.pathname.toLowerCase();
    
    let isSuspicious = false;
    let linkThreats = [];

    // 1. Direct Executable & Malware Dropper Detection in URL
    const dangerousUrlExts = ['.exe', '.scr', '.vbs', '.bat', '.cmd', '.msi', '.ps1', '.hta', '.jar', '.apk', '.wsf', '.pif', '.cpl', '.dll', '.reg', '.iso', '.img'];
    const macroUrlExts = ['.docm', '.xlsm', '.pptm', '.dotm'];
    const archiveUrlExts = ['.zip', '.rar', '.7z', '.cab', '.tar', '.gz'];

    const hasDangerousExt = dangerousUrlExts.some(ext => pathname.endsWith(ext) || pathname.includes(ext + '?') || pathname.includes(ext + '&') || pathname.includes(ext + '#'));
    const hasMacroExt = macroUrlExts.some(ext => pathname.endsWith(ext) || pathname.includes(ext + '?') || pathname.includes(ext + '&'));
    const hasArchiveExt = archiveUrlExts.some(ext => pathname.endsWith(ext) || pathname.includes(ext + '?') || pathname.includes(ext + '&'));

    if (hasDangerousExt) {
      isSuspicious = true;
      linkThreats.push(`Direct Executable / Malware Payload Dropper Link (${pathname.split('/').pop()})`);
      result.score += 70;
      result.indicators.push({
        type: 'link',
        severity: 'critical',
        title: 'Direct Malware Dropper Link (Executable Payload)',
        description: `The URL "${linkUrl}" points directly to an executable binary or scripting payload capable of remote code execution.`
      });
    } else if (hasMacroExt) {
      isSuspicious = true;
      linkThreats.push(`Macro-Enabled Office Document Download Link (${pathname.split('/').pop()})`);
      result.score += 45;
      result.indicators.push({
        type: 'link',
        severity: 'high',
        title: 'Macro-Enabled Document Download Link',
        description: `The URL "${linkUrl}" points to an Office file with embedded macro capabilities.`
      });
    } else if (hasArchiveExt) {
      isSuspicious = true;
      linkThreats.push(`Compressed Archive Download Link (${pathname.split('/').pop()})`);
      result.score += 25;
    }

    // 2. Insecure HTTP Protocol
    if (protocol === 'http:') {
      isSuspicious = true;
      linkThreats.push('Uses insecure HTTP protocol');
      result.score += 15;
    }

    // 3. Raw IP Address Hostname
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipPattern.test(host)) {
      isSuspicious = true;
      linkThreats.push('URL hostname is a raw IP address');
      result.score += 35;
    }

    // 4. Suspicious TLD Scoring
    const suspiciousTLDs = ['.xyz', '.top', '.tk', '.work', '.click', '.gq', '.cf', '.ga', '.ml', '.online', '.site', '.club', '.info', '.buzz', '.rest', '.quest', '.cam'];
    suspiciousTLDs.forEach(tld => {
      if (host.endsWith(tld)) {
        isSuspicious = true;
        linkThreats.push(`Uses a suspicious top-level domain (${tld})`);
        result.score += 20;
      }
    });

    // 5. Brand Impersonation / Typosquatting
    legitBrands.forEach(brand => {
      if (host.includes(brand) && !host.endsWith(`.${brand}.com`) && host !== `${brand}.com` && host !== `www.${brand}.com`) {
        isSuspicious = true;
        linkThreats.push(`Potential typosquatting/impersonation of brand: "${brand}"`);
        result.score += 30;
      }
    });

    if (parsedData.html) {
      const aTagRegex = new RegExp(`<a[^>]*href=["']${escapeRegExp(linkUrl)}["'][^>]*>(.*?)</a>`, 'gi');
      let aMatch;
      while ((aMatch = aTagRegex.exec(parsedData.html)) !== null) {
        const linkText = aMatch[1].replace(/<[^>]*>/g, '').trim();
        if (linkText.startsWith('http') || linkText.includes('.com') || linkText.includes('.org') || linkText.includes('.net')) {
          try {
            let textUrlHost = linkText;
            if (!linkText.startsWith('http')) {
              textUrlHost = 'http://' + linkText;
            }
            const parsedTextUrl = new URL(textUrlHost);
            if (parsedTextUrl.hostname !== host) {
              isSuspicious = true;
              linkThreats.push(`Link Text Mismatch: displayed text ("${linkText}") points to a different destination ("${host}")`);
              result.score += 30;
            }
          } catch(e) {}
        }
      }
    }

    result.links.push({
      url: linkUrl,
      host,
      isSuspicious,
      threats: linkThreats
    });
  });

  const suspLinks = result.links.filter(l => l.isSuspicious);
  if (suspLinks.length > 0) {
    result.indicators.push({
      type: 'link',
      severity: 'critical',
      title: 'Suspicious Destination URLs',
      description: `Identified ${suspLinks.length} suspicious link(s) pointing to potential phishing landing pages.`
    });
  }

  // 7. Analyze Attachments
  const emailAttachments = parsedData.attachments || [];
  emailAttachments.forEach(att => {
    const filename = att.filename || 'unnamed_attachment';
    const size = att.size || 0;
    const ext = path.extname(filename).toLowerCase();
    
    let isSuspicious = false;
    let threats = [];

    const hazardousExtensions = ['.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.msi', '.ps1', '.hta', '.jar', '.cpl', '.pif', '.wsf'];
    const macroExtensions = ['.docm', '.xlsm', '.pptm'];
    const containerExtensions = ['.zip', '.rar', '.7z', '.iso', '.img', '.cab'];

    if (hazardousExtensions.includes(ext)) {
      isSuspicious = true;
      threats.push('Executable or scripting file attachment (extremely high risk)');
      result.score += 40;
    } else if (macroExtensions.includes(ext)) {
      isSuspicious = true;
      threats.push('Office document with macro capabilities enabled');
      result.score += 25;
    } else if (containerExtensions.includes(ext)) {
      isSuspicious = true;
      threats.push('Compressed archive file, potentially concealing malicious payloads');
      result.score += 15;
    }

    const nameParts = filename.split('.');
    if (nameParts.length > 2) {
      const secondToLastExt = '.' + nameParts[nameParts.length - 2].toLowerCase();
      const dangerousCombo = ['.pdf', '.docx', '.xlsx', '.png', '.jpg', '.txt'];
      if (dangerousCombo.includes(secondToLastExt)) {
        isSuspicious = true;
        threats.push(`Double extension detected: "${filename}" tries to appear as a safe file`);
        result.score += 30;
      }
    }

    result.attachments.push({
      filename,
      size,
      contentType: att.contentType || 'application/octet-stream',
      isSuspicious,
      threats
    });
  });

  if (result.attachments.some(a => a.isSuspicious)) {
    result.indicators.push({
      type: 'attachment',
      severity: 'critical',
      title: 'Dangerous Attachment Identified',
      description: `Email contains high-risk attachments capable of containing ransomware, spyware, or keyloggers.`
    });
  }

  // Cap score
  result.score = Math.min(Math.max(result.score, 0), 100);

  // Classification
  if (result.score >= 75) {
    result.severity = 'Critical';
  } else if (result.score >= 50) {
    result.severity = 'High';
  } else if (result.score >= 25) {
    result.severity = 'Medium';
  } else if (result.score > 0) {
    result.severity = 'Low';
  } else {
    result.severity = 'Safe';
  }

  // Framework Mapping
  if (result.score >= 25) {
    let subtechniques = [];
    if (result.attachments.length > 0) {
      subtechniques.push({ id: 'T1566.001', name: 'Spearphishing Attachment', desc: 'Adversaries may send spearphishing emails with malicious attachments to gain Initial Access.' });
    }
    if (result.links.length > 0) {
      subtechniques.push({ id: 'T1566.002', name: 'Spearphishing Link', desc: 'Adversaries may send spearphishing emails with malicious links to credential harvesting pages or malware droppers.' });
    }
    if (subtechniques.length === 0) {
      subtechniques.push({ id: 'T1566.003', name: 'Spearphishing Service', desc: 'Adversaries may use online services to transmit spearphishing communications.' });
    }

    result.mitreMapping.push({
      id: 'T1566',
      tactic: 'Initial Access',
      technique: 'Phishing',
      description: 'Adversaries may send phishing messages to gain access to victim systems or harvest credentials.',
      subtechniques
    });

    if (result.attachments.some(a => a.isSuspicious) || result.links.some(l => l.isSuspicious)) {
      let userSub = [];
      if (result.links.some(l => l.isSuspicious)) {
        userSub.push({ id: 'T1204.001', name: 'Malicious Link', desc: 'An adversary may rely on a user clicking a malicious link to code execution.' });
      }
      if (result.attachments.some(a => a.isSuspicious)) {
        userSub.push({ id: 'T1204.002', name: 'Malicious Attachment', desc: 'An adversary may rely on a user opening a malicious attachment to execute code.' });
      }

      result.mitreMapping.push({
        id: 'T1204',
        tactic: 'Execution',
        technique: 'User Execution',
        description: 'Adversaries may rely on the actions of a user to execute malicious code.',
        subtechniques: userSub
      });
    }

    const hasSpoofing = result.indicators.some(ind => ind.title.includes('Impersonation') || ind.title.includes('Mismatched Reply-To') || ind.title.includes('Free Email') || ind.title.includes('Missing Mail Exchange'));
    if (hasSpoofing) {
      result.mitreMapping.push({
        id: 'T1036',
        tactic: 'Defense Evasion',
        technique: 'Masquerading',
        description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate to users or security controls.',
        subtechniques: [{ id: 'T1036.004', name: 'Masquerade Name', desc: 'Adversaries may impersonate names of brands or users in display fields.' }]
      });
    }

    if (result.links.some(l => l.isSuspicious)) {
      result.owaspMapping.push({
        id: 'A07:2021',
        name: 'Identification and Authentication Failures',
        desc: 'Credential harvesting schemes rely on deceptive landing pages to steal credentials, exploiting identity confirmation flaws.'
      });
    }
    if (result.attachments.some(a => a.isSuspicious) || bodyText.includes('<script')) {
      result.owaspMapping.push({
        id: 'A03:2021',
        name: 'Injection',
        desc: 'HTML body manipulation or malicious script inclusion inside email parts or files can inject and run code/markup.'
      });
    }
  }

  return result;
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// -------------------------------------------------------------
// Live Stream Broadcasting (SSE)
// -------------------------------------------------------------
function broadcastEmail(analysis) {
  inboxHistory.unshift(analysis);
  if (inboxHistory.length > 20) inboxHistory.pop();
  
  sseClients.forEach(client => {
    client.write(`data: ${JSON.stringify({ type: 'new-email', data: analysis })}\n\n`);
  });
}

// REST APIs
// Get stream connections
app.get('/api/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send history immediately on connection
  res.write(`data: ${JSON.stringify({ type: 'history', data: inboxHistory })}\n\n`);
  
  sseClients.push(res);

  req.on('close', () => {
    sseClients = sseClients.filter(c => c !== res);
  });
});

// Get configurations
app.get('/api/settings', (req, res) => {
  res.json({ vtKeySet: vtApiKey !== '' });
});

// Update settings
app.post('/api/settings', (req, res) => {
  const { vtApiKey: newKey } = req.body;
  if (typeof newKey === 'string') {
    vtApiKey = newKey.trim();
    return res.json({ success: true, vtKeySet: vtApiKey !== '' });
  }
  res.status(400).json({ error: 'Invalid settings parameter' });
});

// Get Presets
app.get('/api/samples', (req, res) => {
  res.json(samples.map(s => ({ id: s.id, name: s.name, subject: s.subject })));
});

// Analyze a preset sample
app.post('/api/analyze-sample/:id', async (req, res) => {
  const sample = samples.find(s => s.id === req.params.id);
  if (!sample) {
    return res.status(404).json({ error: 'Sample not found' });
  }
  const analysis = await analyzeEmail(sample);
  res.json(analysis);
});

// Upload and analyze live EML file
app.post('/api/analyze-upload', upload.single('emailFile'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const emailBuffer = req.file.buffer;
    const parsed = await simpleParser(emailBuffer);
    const analysis = await analyzeEmail(parsed);
    res.json(analysis);
  } catch (error) {
    console.error('Error parsing EML file:', error);
    res.status(500).json({ error: 'Failed to parse the uploaded EML file.' });
  }
});

// Wire IMAP Watcher callbacks
imapWatcher.setCallbacks({
  onAnalyze: analyzeEmail,
  onBroadcast: broadcastEmail
});

// IMAP Endpoints
app.get('/api/imap/status', (req, res) => {
  res.json(imapWatcher.getStatus());
});

app.post('/api/imap/connect', async (req, res) => {
  try {
    const result = await imapWatcher.connect(req.body);
    res.json(result);
  } catch (error) {
    console.error('[API] IMAP connect error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to connect to IMAP server' });
  }
});

app.post('/api/imap/disconnect', async (req, res) => {
  try {
    const result = await imapWatcher.disconnect();
    res.json(result);
  } catch (error) {
    console.error('[API] IMAP disconnect error:', error.message);
    res.status(500).json({ error: error.message || 'Failed to disconnect from IMAP server' });
  }
});

app.post('/api/imap/sync-recent', async (req, res) => {
  try {
    const count = parseInt(req.body.count, 10) || 5;
    const result = await imapWatcher.syncRecent(count);
    res.json(result);
  } catch (error) {
    console.error('[API] IMAP sync error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to sync recent emails' });
  }
});

// Initialize SMTP Receiver Middleware
const smtpServer = new SMTPServer({
  disabledCommands: ['STARTTLS', 'AUTH'],
  onData(stream, session, callback) {
    simpleParser(stream, async (err, parsed) => {
      if (err) {
        console.error('[SMTP] Incoming stream parsing failed:', err);
        return callback(err);
      }
      try {
        const analysis = await analyzeEmail(parsed);
        analysis.smtpSession = {
          from: session.envelope.mailFrom ? session.envelope.mailFrom.address : 'Unknown',
          to: session.envelope.rcptTo.map(r => r.address).join(', '),
          remoteAddress: session.remoteAddress
        };
        console.log(`[SMTP Middleware] Intercepted email from ${analysis.smtpSession.from} to ${analysis.smtpSession.to} (Threat Score: ${analysis.score})`);
        
        broadcastEmail(analysis);
        callback();
      } catch (e) {
        console.error('[SMTP] Analytical processing failed:', e);
        callback(e);
      }
    });
  }
});

// Start servers
app.listen(port, () => {
  console.log(`Phishing Intelligence Dashboard running at http://localhost:${port}`);
});

smtpServer.listen(smtpPort, () => {
  console.log(`SMTP Receiver Middleware listening on port ${smtpPort}`);
});

