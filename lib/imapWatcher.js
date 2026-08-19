const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');

class ImapWatcher {
  constructor(options = {}) {
    this.client = null;
    this.currentLock = null;
    this.status = {
      connected: false,
      isWatching: false,
      host: '',
      port: 993,
      user: '',
      mailbox: 'INBOX',
      error: null,
      lastSync: null
    };
    this.analyzeCallback = options.onAnalyze || null;
    this.broadcastCallback = options.onBroadcast || null;
    this.isStopping = false;
  }

  setCallbacks({ onAnalyze, onBroadcast }) {
    if (onAnalyze) this.analyzeCallback = onAnalyze;
    if (onBroadcast) this.broadcastCallback = onBroadcast;
  }

  getStatus() {
    return {
      connected: this.status.connected,
      isWatching: this.status.isWatching,
      host: this.status.host,
      port: this.status.port,
      user: this.status.user ? this.maskEmail(this.status.user) : '',
      rawUser: this.status.user || '',
      mailbox: this.status.mailbox,
      error: this.status.error,
      lastSync: this.status.lastSync
    };
  }

  maskEmail(email) {
    if (!email || !email.includes('@')) return email;
    const [name, domain] = email.split('@');
    if (name.length <= 2) return `${name[0]}***@${domain}`;
    return `${name.slice(0, 2)}***${name.slice(-1)}@${domain}`;
  }

  async connect(config) {
    // If already connected, disconnect first
    if (this.client) {
      await this.disconnect();
    }

    const host = config.host || 'imap.gmail.com';
    const port = Number(config.port) || 993;
    const secure = config.secure !== undefined ? Boolean(config.secure) : (port === 993);
    const user = (config.user || '').trim();
    let pass = (config.pass || '').trim();
    // Google App Passwords are 16 letters usually formatted with spaces: "xxxx xxxx xxxx xxxx"
    if (host.includes('gmail.com') || user.toLowerCase().endsWith('@gmail.com') || host.includes('google')) {
      pass = pass.replace(/\s+/g, '');
    }

    const mailbox = config.mailbox || 'INBOX';

    if (!user || !pass) {
      throw new Error('Email username and password/app-password are required.');
    }

    this.isStopping = false;
    this.status.host = host;
    this.status.port = port;
    this.status.user = user;
    this.status.mailbox = mailbox;
    this.status.error = null;

    const client = new ImapFlow({
      host,
      port,
      secure,
      auth: {
        user,
        pass
      },
      logger: false,
      emitLogs: false
    });

    this.client = client;

    // Handle connection error events
    client.on('error', (err) => {
      console.error('[IMAP Watcher] Client error:', err.message);
      this.status.error = err.message;
      if (!this.isStopping) {
        this.status.connected = false;
        this.status.isWatching = false;
      }
    });

    client.on('close', () => {
      console.log('[IMAP Watcher] Connection closed.');
      if (!this.isStopping) {
        this.status.connected = false;
        this.status.isWatching = false;
      }
    });

    try {
      console.log(`[IMAP Watcher] Connecting to ${host}:${port} as ${user}...`);
      await client.connect();
      this.status.connected = true;
      this.status.lastSync = new Date();
      console.log(`[IMAP Watcher] Successfully authenticated!`);

      // Start watching mailbox in the background (which also syncs recent emails)
      this.startWatching(mailbox).catch((err) => {
        console.error('[IMAP Watcher] Watch loop error:', err.message);
      });

      return {
        success: true,
        message: `Connected to ${host} as ${user}`,
        status: this.getStatus()
      };
    } catch (err) {
      this.status.connected = false;
      this.status.isWatching = false;
      
      let detailedMsg = err.responseText || err.responseStatus || err.message;
      if (err.serverResponseCode === 'AUTHENTICATIONFAILED' || detailedMsg.includes('Command failed') || detailedMsg.includes('Invalid credentials')) {
        if (host.includes('gmail.com') || user.toLowerCase().endsWith('@gmail.com')) {
          detailedMsg = 'Gmail Authentication Failed. Note: You must use a 16-character Google App Password (not your regular Gmail password) and ensure IMAP is enabled in Gmail Settings.';
        } else {
          detailedMsg = 'IMAP Authentication Failed. Please verify your username and password/app-password.';
        }
      }

      this.status.error = detailedMsg;
      this.client = null;
      console.error(`[IMAP Watcher] Connection error: ${detailedMsg} (Raw: ${err.message})`);
      throw new Error(detailedMsg);
    }
  }

  async startWatching(mailboxName = 'INBOX') {
    if (!this.client || !this.status.connected) return;

    try {
      const lock = await this.client.getMailboxLock(mailboxName);
      this.currentLock = lock;
      this.status.isWatching = true;
      console.log(`[IMAP Watcher] Mailbox locked: ${mailboxName}. Syncing recent emails...`);

      // 1. Immediately scan recent messages
      try {
        await this.fetchRecentMessages(5);
      } catch (syncErr) {
        console.error('[IMAP Watcher] Initial sync error:', syncErr.message);
      }

      // 2. Listen for new messages while in IDLE
      this.client.on('exists', async (data) => {
        console.log(`[IMAP Watcher] New email event detected! Total messages: ${data.count}`);
        await this.fetchAndProcessLatest(data.count);
      });

      console.log(`[IMAP Watcher] Starting IDLE push listener on ${mailboxName}...`);

      // 3. Loop IDLE while connected
      while (this.status.connected && !this.isStopping) {
        try {
          await this.client.idle();
        } catch (idleErr) {
          if (this.isStopping) break;
          console.log('[IMAP Watcher] Idle reset or timeout, resuming...');
        }
      }
    } catch (err) {
      if (!this.isStopping) {
        console.error('[IMAP Watcher] Error in startWatching:', err.message);
        this.status.error = err.message;
      }
    } finally {
      if (this.currentLock) {
        try {
          this.currentLock.release();
        } catch(e) {}
        this.currentLock = null;
      }
      this.status.isWatching = false;
    }
  }

  async fetchRecentMessages(count = 5) {
    if (!this.client || !this.status.connected) {
      throw new Error('IMAP is not currently connected.');
    }

    const mailbox = this.client.mailbox;
    const totalMessages = mailbox ? (mailbox.exists || 0) : 0;

    if (totalMessages === 0) {
      return { count: 0, results: [], message: 'Mailbox is empty.' };
    }

    const startSeq = Math.max(1, totalMessages - count + 1);
    const range = `${startSeq}:${totalMessages}`;

    console.log(`[IMAP Watcher] Fetching recent messages in range ${range} (Total: ${totalMessages})...`);

    const results = [];
    for await (const message of this.client.fetch(range, { source: true, envelope: true })) {
      if (message.source && this.analyzeCallback) {
        try {
          const parsed = await simpleParser(message.source);
          const analysis = await this.analyzeCallback(parsed);
          analysis.sourceType = 'IMAP Sync';
          analysis.imapDetails = {
            mailbox: this.status.mailbox,
            user: this.status.user,
            seq: message.seq,
            date: parsed.date || new Date()
          };

          if (this.broadcastCallback) {
            this.broadcastCallback(analysis);
          }

          results.push(analysis);
        } catch (e) {
          console.error(`[IMAP Watcher] Error analyzing message seq ${message.seq}:`, e.message);
        }
      }
    }

    this.status.lastSync = new Date();
    return {
      count: results.length,
      results,
      message: `Successfully analyzed ${results.length} recent email(s) from ${this.status.mailbox}.`
    };
  }

  async fetchAndProcessLatest(seqNumber) {
    if (!this.client || !this.status.connected) return;

    try {
      const message = await this.client.fetchOne(seqNumber, { source: true, envelope: true });
      if (!message || !message.source) return;

      const parsed = await simpleParser(message.source);
      
      let analysis = null;
      if (this.analyzeCallback) {
        analysis = await this.analyzeCallback(parsed);
        analysis.sourceType = 'IMAP Live Sync';
        analysis.imapDetails = {
          mailbox: this.status.mailbox,
          user: this.status.user,
          seq: seqNumber,
          date: parsed.date || new Date()
        };

        if (this.broadcastCallback) {
          this.broadcastCallback(analysis);
        }
      }

      this.status.lastSync = new Date();
      console.log(`[IMAP Watcher] Scanned new email: "${parsed.subject || '(No Subject)'}" - Risk Score: ${analysis ? analysis.score : 'N/A'}`);
    } catch (err) {
      console.error('[IMAP Watcher] Error fetching latest message:', err.message);
    }
  }

  async syncRecent(count = 5) {
    if (!this.client || !this.status.connected) {
      throw new Error('IMAP is not currently connected. Please connect first.');
    }

    if (this.currentLock) {
      return await this.fetchRecentMessages(count);
    } else {
      const lock = await this.client.getMailboxLock(this.status.mailbox || 'INBOX');
      try {
        return await this.fetchRecentMessages(count);
      } finally {
        lock.release();
      }
    }
  }

  async disconnect() {
    this.isStopping = true;
    this.status.connected = false;
    this.status.isWatching = false;

    if (this.currentLock) {
      try {
        this.currentLock.release();
      } catch (e) {}
      this.currentLock = null;
    }

    if (this.client) {
      try {
        console.log('[IMAP Watcher] Disconnecting IMAP client...');
        await this.client.logout();
      } catch (err) {
        // Ignore logout errors on already closed socket
      } finally {
        this.client = null;
      }
    }

    console.log('[IMAP Watcher] Disconnected successfully.');
    return { success: true, status: this.getStatus() };
  }
}

module.exports = ImapWatcher;
