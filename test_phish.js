const net = require('net');

// Pre-crafted raw RFC 822 phishing email scenarios
const testScenarios = [
  {
    name: '1. Microsoft Credential Harvesting Attack (Mismatched Links + Fake Urgency)',
    raw: `From: "Microsoft Security Team" <security-alerts@microsoft-verify-login.xyz>
To: <target-user@company.com>
Subject: URGENT: Your Microsoft 365 Password will expire in 24 hours
Date: ${new Date().toUTCString()}
Message-ID: <msg-${Date.now()}-1@phish-sim.local>
Authentication-Results: spf=fail (sender IP is 198.51.100.42) smtp.mailfrom=microsoft-verify-login.xyz; dkim=fail; dmarc=fail
Reply-To: credential-collector@hacker-domain.xyz
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Dear User,</p>
<p>Your Microsoft 365 account password will <strong>expire in 24 hours</strong>. Immediate action is required to avoid account suspension.</p>
<p>Please verify your password immediately to retain access:</p>
<p><a href="http://login-microsoft-office365.online-verify.xyz/auth.php">https://portal.office.com/settings/security</a></p>
<p>Thank you,<br>Microsoft Security Operations</p>
`
  },
  {
    name: '2. CEO Impersonation & BEC Wire Fraud (Display Name Spoofing)',
    raw: `From: "Satya Nadella (CEO)" <ceo.executive.urgent@gmail.com>
To: <target-user@company.com>
Subject: Quick Task - Need Apple Gift Cards Urgently
Date: ${new Date().toUTCString()}
Message-ID: <msg-${Date.now()}-2@phish-sim.local>
Authentication-Results: spf=pass smtp.mailfrom=gmail.com
Reply-To: ceo-private-reply@anonymousmail.net
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hi,

I am currently in an executive board meeting and cannot take phone calls.
I need you to process an urgent client gift card request immediately.
Please purchase 5 Apple Gift Cards ($100 each) and email me photos of the back codes right away.

I will reimburse you via corporate wire transfer when I get back to my desk.

Thanks,
Satya Nadella
Chief Executive Officer
`
  },
  {
    name: '3. Malicious Double-Extension Attachment & Overdue Invoice Scare',
    raw: `From: "Accounts Payable Dept" <billing@legit-accounting-firm.com>
To: <target-user@company.com>
Subject: FINAL NOTICE: Overdue Payment for Invoice #INV-98294
Date: ${new Date().toUTCString()}
Message-ID: <msg-${Date.now()}-3@phish-sim.local>
Authentication-Results: spf=pass smtp.mailfrom=legit-accounting-firm.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_12345_67890"

------=_Part_12345_67890
Content-Type: text/plain; charset=utf-8

Please find attached your overdue invoice #INV-98294. 
Immediate payment is required within 24 hours to prevent legal action.

------=_Part_12345_67890
Content-Type: application/octet-stream; name="Invoice_Report_98294.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Report_98294.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUKJCRQAAAAAAAAAA==
------=_Part_12345_67890--
`
  },
  {
    name: '4. Legitimate Clean Email (Benign Verification Baseline)',
    raw: `From: "GitHub Support" <noreply@github.com>
To: <target-user@company.com>
Subject: [GitHub] New login detected for your account
Date: ${new Date().toUTCString()}
Message-ID: <msg-${Date.now()}-4@phish-sim.local>
Authentication-Results: spf=pass (sender IP is 140.82.115.4) smtp.mailfrom=github.com; dkim=pass header.i=@github.com; dmarc=pass
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Hey developer,</p>
<p>A new login was detected to your GitHub account from IP 192.0.2.1.</p>
<p>If this was you, no action is needed. If you did not initiate this login, please visit <a href="https://github.com/settings/security">https://github.com/settings/security</a> to secure your credentials.</p>
`
  },
  {
    name: '5. Direct Malware Dropper Executable Link (Ldrdubl2132.exe)',
    raw: `From: "Security Notification" <security-patch@bmpincorporated.com>
To: <target-user@company.com>
Subject: Critical System Update: Download and run the patch immediately
Date: ${new Date().toUTCString()}
Message-ID: <msg-${Date.now()}-5@phish-sim.local>
Authentication-Results: spf=pass smtp.mailfrom=bmpincorporated.com
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>A critical vulnerability has been identified. Immediate action is required.</p>
<p>Please download and run the mandatory security update binary:</p>
<p><a href="https://bmpincorporated.com/dubl2/dubl22allremriki/Ldrdubl2132.exe">Download and Execute Security Patch (Ldrdubl2132.exe)</a></p>
`
  }
];

function sendEmailToSmtp(scenario) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ port: 2525, host: '127.0.0.1' }, () => {
      // SMTP Handshake
      let stage = 0;
      client.on('data', (data) => {
        const response = data.toString();
        if (response.startsWith('220') && stage === 0) {
          client.write('HELO localhost\r\n');
          stage = 1;
        } else if (response.startsWith('250') && stage === 1) {
          client.write('MAIL FROM:<attacker@phishing-test.com>\r\n');
          stage = 2;
        } else if (response.startsWith('250') && stage === 2) {
          client.write('RCPT TO:<victim@target.com>\r\n');
          stage = 3;
        } else if (response.startsWith('250') && stage === 3) {
          client.write('DATA\r\n');
          stage = 4;
        } else if (response.startsWith('354') && stage === 4) {
          client.write(scenario.raw + '\r\n.\r\n');
          stage = 5;
        } else if (response.startsWith('250') && stage === 5) {
          client.write('QUIT\r\n');
          client.end();
          resolve();
        }
      });
    });

    client.on('error', (err) => {
      reject(err);
    });
  });
}

async function runTests() {
  console.log('================================================================');
  console.log('  PhishGuard SOC // Automated Phishing Simulation Test Suite    ');
  console.log('================================================================\n');

  for (let i = 0; i < testScenarios.length; i++) {
    const scenario = testScenarios[i];
    console.log(`[+] Transmitting Scenario ${i + 1}/${testScenarios.length}: ${scenario.name}...`);
    try {
      await sendEmailToSmtp(scenario);
      console.log(`    ✓ Successfully injected into SMTP Gateway (Port 2525)!`);
      console.log(`    → Check dashboard at http://localhost:3000 to see real-time analysis.\n`);
      // Short delay between injections
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) {
      console.error(`    ✗ Failed to connect to SMTP port 2525:`, e.message);
    }
  }

  console.log('================================================================');
  console.log('  All test scenarios delivered! Open http://localhost:3000      ');
  console.log('================================================================');
}

runTests();
