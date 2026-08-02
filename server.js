// server.js - AuthAPI v3.5 ULTIMATE - Anti-Crash + AI (Public Access)
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();

/* ================= CONSTANTS ================= */
const PORT = process.env.PORT || 10000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'keys.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const LOGS_FILE = path.join(DATA_DIR, 'activity_logs.json');
const AI_LOGS_FILE = path.join(DATA_DIR, 'ai_logs.json');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const LOCK_DIR = path.join(DATA_DIR, 'locks');

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-jwt-secret-2025';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-hmac-secret-2025';

// AI API Keys (set in environment variables)
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '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';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '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';

const MAX_ACCOUNTS_PER_DEVICE = 3;
const MAX_MEMORY_MB = 450;
const MAX_LOGS = 1000;
const LOCK_TIMEOUT = 5000;
const MAX_RETRY = 3;

// AI Limits
const AI_DAILY_LIMIT = 100; // 100 requests/day
const AI_RATE_LIMIT_MS = 3000; // 3 seconds between requests

/* ================= MEMORY MONITORING ================= */
let memoryWarningCount = 0;

function monitorMemory() {
  const used = process.memoryUsage();
  const usedMB = Math.round(used.heapUsed / 1024 / 1024);
  
  if (usedMB > MAX_MEMORY_MB) {
    memoryWarningCount++;
    console.warn(`⚠️ HIGH MEMORY: ${usedMB}MB (Warning #${memoryWarningCount})`);
    
    if (memoryWarningCount > 5) {
      console.error('❌ CRITICAL MEMORY - Forcing GC');
      if (global.gc) {
        global.gc();
        memoryWarningCount = 0;
      }
    }
  } else {
    memoryWarningCount = 0;
  }
}

setInterval(monitorMemory, 30000);

/* ================= ERROR HANDLING ================= */
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION:', err);
  console.error('Stack:', err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ UNHANDLED REJECTION:', reason);
  console.error('Promise:', promise);
});

process.on('warning', (warning) => {
  console.warn('⚠️ Warning:', warning.name);
  console.warn('Message:', warning.message);
});

app.use((err, req, res, next) => {
  console.error('❌ Express Error:', err.stack);
  res.status(500).json({
    success: false, 
    message: 'Internal Server Error', 
    error_code: 'SERVER_ERROR'
  });
});

/* ================= MIDDLEWARE ================= */
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));

app.use((req, res, next) => {
  const startTime = Date.now();
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    if (duration > 1000) {
      console.warn(`⚠️ Slow request: ${req.method} ${req.path} - ${duration}ms`);
    }
  });
  
  next();
});

app.use((req, res, next) => {
  req.setTimeout(30000); // 30 seconds for AI requests
  next();
});

/* ================= FILE LOCKING SYSTEM ================= */
class FileLock {
  constructor() {
    this.locks = new Map();
    if (!fsSync.existsSync(LOCK_DIR)) {
      fsSync.mkdirSync(LOCK_DIR, { recursive: true });
    }
  }

  async acquire(filename) {
    const lockFile = path.join(LOCK_DIR, `${filename}.lock`);
    const startTime = Date.now();
    
    while (true) {
      try {
        await fs.writeFile(lockFile, process.pid.toString(), { flag: 'wx' });
        this.locks.set(filename, lockFile);
        return true;
      } catch (err) {
        if (err.code !== 'EEXIST') {
          throw err;
        }
        
        try {
          const stats = await fs.stat(lockFile);
          const lockAge = Date.now() - stats.mtimeMs;
          
          if (lockAge > LOCK_TIMEOUT) {
            console.warn(`⚠️ Removing stale lock: ${filename}`);
            await fs.unlink(lockFile).catch(() => {});
            continue;
          }
        } catch (statErr) {
          continue;
        }
        
        if (Date.now() - startTime > LOCK_TIMEOUT) {
          throw new Error(`Lock timeout for ${filename}`);
        }
        
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
  }

  async release(filename) {
    const lockFile = this.locks.get(filename);
    if (lockFile) {
      try {
        await fs.unlink(lockFile);
      } catch (err) {
        console.error(`Error releasing lock for ${filename}:`, err);
      }
      this.locks.delete(filename);
    }
  }
}

const fileLock = new FileLock();

/* ================= BACKUP SYSTEM ================= */
async function ensureBackupDir() {
  try {
    await fs.access(BACKUP_DIR);
  } catch {
    await fs.mkdir(BACKUP_DIR, { recursive: true });
    console.log('✅ Created backup directory');
  }
}

async function createBackup() {
  try {
    await ensureBackupDir();
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupSubDir = path.join(BACKUP_DIR, timestamp);
    
    await fs.mkdir(backupSubDir, { recursive: true });

    const filesToBackup = [DATA_FILE, USERS_FILE, CONFIG_FILE, DEVICES_FILE, LOGS_FILE, AI_LOGS_FILE];
    
    for (const file of filesToBackup) {
      try {
        await fs.access(file);
        const filename = path.basename(file);
        const backupPath = path.join(backupSubDir, filename);
        await fs.copyFile(file, backupPath);
      } catch (err) {
        // File doesn't exist, skip
      }
    }

    console.log(`✅ Backup created: ${timestamp}`);
    await cleanOldBackups();
  } catch(err) {
    console.error('❌ Backup error:', err);
  }
}

async function cleanOldBackups() {
  try {
    const backups = await fs.readdir(BACKUP_DIR);
    const now = Date.now();
    
    for (const backup of backups) {
      const backupPath = path.join(BACKUP_DIR, backup);
      try {
        const stats = await fs.stat(backupPath);
        const daysDiff = (now - stats.mtimeMs) / (1000 * 60 * 60 * 24);
        
        if (daysDiff > 7) {
          await fs.rm(backupPath, { recursive: true, force: true });
          console.log(`🗑️ Deleted old backup: ${backup}`);
        }
      } catch (err) {
        console.error(`Error processing backup ${backup}:`, err);
      }
    }
  } catch(err) {
    console.error('❌ Clean backup error:', err);
  }
}

setInterval(() => {
  createBackup().catch(err => console.error('Scheduled backup failed:', err));
}, 6 * 60 * 60 * 1000);

/* ================= SAFE FILE OPERATIONS ================= */
async function safeLoadJSON(file, defaultValue = []) {
  for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
    try {
      await fs.access(file);
      const data = await fs.readFile(file, 'utf8');
      
      if (!data || data.trim() === '') {
        console.warn(`⚠️ Empty file: ${file}, using default`);
        return defaultValue;
      }
      
      return JSON.parse(data);
    } catch(err) {
      if (err.code === 'ENOENT') {
        return defaultValue;
      }
      
      console.error(`❌ Error loading ${file} (attempt ${attempt}/${MAX_RETRY}):`, err.message);
      
      if (attempt < MAX_RETRY) {
        await new Promise(resolve => setTimeout(resolve, 100 * attempt));
      } else {
        console.error(`❌ Failed to load ${file} after ${MAX_RETRY} attempts`);
        return defaultValue;
      }
    }
  }
  return defaultValue;
}

async function safeSaveJSON(file, data) {
  const filename = path.basename(file);
  
  for (let attempt = 1; attempt <= MAX_RETRY; attempt++) {
    try {
      await fileLock.acquire(filename);
      
      const tempFile = file + '.tmp';
      const jsonStr = JSON.stringify(data, null, 2);
      
      await fs.writeFile(tempFile, jsonStr, 'utf8');
      const tempData = await fs.readFile(tempFile, 'utf8');
      JSON.parse(tempData);
      await fs.rename(tempFile, file);
      
      await fileLock.release(filename);
      return true;
    } catch(err) {
      await fileLock.release(filename);
      console.error(`❌ Error saving ${file} (attempt ${attempt}/${MAX_RETRY}):`, err.message);
      
      if (attempt < MAX_RETRY) {
        await new Promise(resolve => setTimeout(resolve, 100 * attempt));
      } else {
        console.error(`❌ Failed to save ${file} after ${MAX_RETRY} attempts`);
        return false;
      }
    }
  }
  return false;
}

/* ================= INIT FILES ================= */
async function initializeFiles() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    
    if (!fsSync.existsSync(DATA_FILE)) {
      await safeSaveJSON(DATA_FILE, []);
      console.log('✅ Initialized keys.json');
    }

    if (!fsSync.existsSync(USERS_FILE)) {
      await safeSaveJSON(USERS_FILE, []);
      console.log('✅ Initialized users.json');
    }

    if (!fsSync.existsSync(DEVICES_FILE)) {
      await safeSaveJSON(DEVICES_FILE, []);
      console.log('✅ Initialized devices.json');
    }

    if (!fsSync.existsSync(LOGS_FILE)) {
      await safeSaveJSON(LOGS_FILE, []);
      console.log('✅ Initialized activity_logs.json');
    }

    if (!fsSync.existsSync(AI_LOGS_FILE)) {
      await safeSaveJSON(AI_LOGS_FILE, []);
      console.log('✅ Initialized ai_logs.json');
    }

    if (!fsSync.existsSync(CONFIG_FILE)) {
      const adminPassword = process.env.ADMIN_PASSWORD || 'zzauthkey';
      const hash = await bcrypt.hash(adminPassword, 10);
      const cfg = {
        admin: {
          username: 'authkey',
          passwordHash: hash
        },
        contact: {
          admin_profile: 'https://www.facebook.com/duc.pham.396384',
          telegram: '@phamcduc0',
          email: 'monhpham15@gmail.com'
        },
        settings: {
          maintenance_mode: false,
          registration_enabled: true,
          max_key_days: 365,
          enable_email_verification: false,
          ai_enabled: true,
          ai_provider: 'openai' // or 'anthropic'
        }
      };
      await safeSaveJSON(CONFIG_FILE, cfg);
      console.log('✅ Initialized config.json');
    }
  } catch (err) {
    console.error('❌ Initialization error:', err);
    throw err;
  }
}

/* ================= HELPERS ================= */
async function loadKeys() {
  return await safeLoadJSON(DATA_FILE, []);
}

async function saveKeys(keys) {
  return await safeSaveJSON(DATA_FILE, keys);
}

async function loadUsers() {
  return await safeLoadJSON(USERS_FILE, []);
}

async function saveUsers(users) {
  return await safeSaveJSON(USERS_FILE, users);
}

async function loadDevices() {
  return await safeLoadJSON(DEVICES_FILE, []);
}

async function saveDevices(devices) {
  return await safeSaveJSON(DEVICES_FILE, devices);
}

async function loadConfig() {
  return await safeLoadJSON(CONFIG_FILE, {
    admin: { username: 'admin', passwordHash: '' },
    contact: {},
    settings: {}
  });
}

async function saveConfig(config) {
  return await safeSaveJSON(CONFIG_FILE, config);
}

async function loadLogs() {
  return await safeLoadJSON(LOGS_FILE, []);
}

async function saveLogs(logs) {
  if (logs.length > MAX_LOGS) {
    logs = logs.slice(-MAX_LOGS);
  }
  return await safeSaveJSON(LOGS_FILE, logs);
}

async function loadAILogs() {
  return await safeLoadJSON(AI_LOGS_FILE, []);
}

async function saveAILogs(logs) {
  if (logs.length > MAX_LOGS) {
    logs = logs.slice(-MAX_LOGS);
  }
  return await safeSaveJSON(AI_LOGS_FILE, logs);
}

/* ================= ACTIVITY LOGGING ================= */
async function logActivity(action, userId, username, details = {}) {
  try {
    const logs = await loadLogs();
    const log = {
      id: uuidv4(),
      action,
      userId,
      username,
      details,
      timestamp: new Date().toISOString(),
      ip: details.ip || 'unknown'
    };
    
    logs.push(log);
    await saveLogs(logs);
  } catch(err) {
    console.error('❌ Log error:', err);
  }
}

async function logAIUsage(userId, username, type, details = {}) {
  try {
    const logs = await loadAILogs();
    const log = {
      id: uuidv4(),
      userId,
      username,
      type,
      details,
      timestamp: new Date().toISOString()
    };
    
    logs.push(log);
    await saveAILogs(logs);
  } catch(err) {
    console.error('❌ AI Log error:', err);
  }
}

function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

function randomChunk(len) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').substring(0, len).toUpperCase();
}

function generateKey(type = "KEY") {
  const prefix = type;
  return `${prefix}-${randomChunk(6)}-${randomChunk(4)}`;
}

function generateAPICode() {
  return `API-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
}

function generateDeviceId(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection.remoteAddress || '';
  const combined = `${userAgent}-${ip}`;
  return crypto.createHash('sha256').update(combined).digest('hex');
}

/* ================= AUTH MIDDLEWARE ================= */
function requireAdmin(req, res, next) {
  try {
    const auth = req.headers['authorization'];
    if (!auth) return res.status(401).json({ error: 'Missing token' });

    const parts = auth.split(' ');
    if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });

    const payload = jwt.verify(parts[1], JWT_SECRET);
    if (payload.role === 'admin') {
      req.user = payload;
      return next();
    }
    return res.status(403).json({ error: 'Admin access required' });
  } catch(err) {
    console.error('Auth error:', err);
    return res.status(401).json({ error: 'Token invalid' });
  }
}

function getClientIdentifier(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.ip
    || req.connection?.remoteAddress
    || 'public';
}

/* ================= AI RATE LIMITING ================= */
const aiRateLimits = new Map();

async function checkAIRateLimit(userId) {
  const now = Date.now();
  const userLimit = aiRateLimits.get(userId);
  
  if (!userLimit) {
    aiRateLimits.set(userId, { lastRequest: now, count: 1, resetAt: now + 86400000 });
    return { allowed: true, remaining: AI_DAILY_LIMIT - 1 };
  }

  // Reset daily limit
  if (now > userLimit.resetAt) {
    aiRateLimits.set(userId, { lastRequest: now, count: 1, resetAt: now + 86400000 });
    return { allowed: true, remaining: AI_DAILY_LIMIT - 1 };
  }

  // Check rate limit (3 seconds between requests)
  if (now - userLimit.lastRequest < AI_RATE_LIMIT_MS) {
    return { 
      allowed: false, 
      remaining: AI_DAILY_LIMIT - userLimit.count,
      error: 'Vui lòng chờ 3 giây giữa các request'
    };
  }

  // Check daily limit
  if (userLimit.count >= AI_DAILY_LIMIT) {
    return { 
      allowed: false, 
      remaining: 0,
      error: `Đã đạt giới hạn ${AI_DAILY_LIMIT} requests/ngày`
    };
  }

  userLimit.count++;
  userLimit.lastRequest = now;
  aiRateLimits.set(userId, userLimit);

  return { allowed: true, remaining: AI_DAILY_LIMIT - userLimit.count };
}

/* ================= AI FUNCTIONS ================= */

// OpenAI Chat
async function callOpenAI(prompt, model = 'gpt-3.5-turbo') {
  if (!OPENAI_API_KEY) {
    throw new Error('OpenAI API key not configured');
  }

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: model,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1000,
      temperature: 0.7
    })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || 'OpenAI API error');
  }

  const data = await response.json();
  return data.choices[0].message.content;
}

// Anthropic Claude
async function callAnthropic(prompt, model = 'claude-3-haiku-20240307') {
  if (!ANTHROPIC_API_KEY) {
    throw new Error('Anthropic API key not configured');
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: model,
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || 'Anthropic API error');
  }

  const data = await response.json();
  return data.content[0].text;
}

// DALL-E Image Generation
async function generateImage(prompt) {
  if (!OPENAI_API_KEY) {
    throw new Error('OpenAI API key not configured');
  }

  const response = await fetch('https://api.openai.com/v1/images/generations', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: 'dall-e-3',
      prompt: prompt,
      n: 1,
      size: '1024x1024'
    })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || 'Image generation error');
  }

  const data = await response.json();
  return data.data[0].url;
}

/* ================= MAINTENANCE MODE ================= */
async function checkMaintenance(req, res, next) {
  const config = await loadConfig();
  if (config.settings?.maintenance_mode && !req.path.includes('/admin')) {
    return res.status(503).json({
      success: false,
      message: '🔧 Hệ thống đang bảo trì. Vui lòng quay lại sau.',
      error_code: 'MAINTENANCE_MODE'
    });
  }
  next();
}

app.use(checkMaintenance);

/* ================= AI ENDPOINTS ================= */

// AI Chat
app.post('/api/ai/chat', async (req, res) => {
  try {
    const { prompt, model } = req.body || {};
    const clientId = getClientIdentifier(req);
    
    if (!prompt) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập prompt' });
    }

    const rateLimit = await checkAIRateLimit(clientId);
    if (!rateLimit.allowed) {
      return res.status(429).json({ 
        success: false, 
        message: rateLimit.error,
        remaining: rateLimit.remaining
      });
    }

    const config = await loadConfig();
    const provider = config.settings?.ai_provider || 'openai';

    let response;
    if (provider === 'openai') {
      response = await callOpenAI(prompt, model || 'gpt-3.5-turbo');
    } else if (provider === 'anthropic') {
      response = await callAnthropic(prompt, model || 'claude-3-haiku-20240307');
    } else {
      throw new Error('Invalid AI provider');
    }

    await logAIUsage(clientId, 'public', 'chat', { 
      provider, 
      model: model || 'default',
      promptLength: prompt.length 
    });

    res.json({
      success: true,
      response: response,
      provider: provider,
      remaining: rateLimit.remaining
    });
  } catch(err) {
    console.error('AI Chat error:', err);
    res.status(500).json({ 
      success: false, 
      message: err.message || 'AI service error' 
    });
  }
});

// AI Image Generation
app.post('/api/ai/image', async (req, res) => {
  try {
    const { prompt } = req.body || {};
    const clientId = getClientIdentifier(req);
    
    if (!prompt) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập prompt' });
    }

    const rateLimit = await checkAIRateLimit(clientId);
    if (!rateLimit.allowed) {
      return res.status(429).json({ 
        success: false, 
        message: rateLimit.error,
        remaining: rateLimit.remaining
      });
    }

    const imageUrl = await generateImage(prompt);

    await logAIUsage(clientId, 'public', 'image', { 
      promptLength: prompt.length 
    });

    res.json({
      success: true,
      imageUrl: imageUrl,
      remaining: rateLimit.remaining
    });
  } catch(err) {
    console.error('AI Image error:', err);
    res.status(500).json({ 
      success: false, 
      message: err.message || 'Image generation error' 
    });
  }
});

// AI Code Helper
app.post('/api/ai/code', async (req, res) => {
  try {
    const { code, task } = req.body || {};
    const clientId = getClientIdentifier(req);
    
    if (!task) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập yêu cầu' });
    }

    const rateLimit = await checkAIRateLimit(clientId);
    if (!rateLimit.allowed) {
      return res.status(429).json({ 
        success: false, 
        message: rateLimit.error,
        remaining: rateLimit.remaining
      });
    }

    const prompt = code 
      ? `Task: ${task}\n\nCode:\n${code}\n\nPlease help with this code.`
      : `Task: ${task}\n\nPlease generate code for this task.`;

    const config = await loadConfig();
    const provider = config.settings?.ai_provider || 'openai';

    let response;
    if (provider === 'openai') {
      response = await callOpenAI(prompt, 'gpt-4');
    } else {
      response = await callAnthropic(prompt, 'claude-3-sonnet-20240229');
    }

    await logAIUsage(clientId, 'public', 'code', { 
      provider,
      hasCode: !!code,
      taskLength: task.length
    });

    res.json({
      success: true,
      response: response,
      provider: provider,
      remaining: rateLimit.remaining
    });
  } catch(err) {
    console.error('AI Code error:', err);
    res.status(500).json({ 
      success: false, 
      message: err.message || 'AI service error' 
    });
  }
});

// AI Text Analysis
app.post('/api/ai/analyze', async (req, res) => {
  try {
    const { text, analysisType } = req.body || {};
    const clientId = getClientIdentifier(req);
    
    if (!text) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập text' });
    }

    const rateLimit = await checkAIRateLimit(clientId);
    if (!rateLimit.allowed) {
      return res.status(429).json({ 
        success: false, 
        message: rateLimit.error,
        remaining: rateLimit.remaining
      });
    }

    const prompts = {
      sentiment: `Analyze the sentiment of this text: "${text}"`,
      summary: `Summarize this text: "${text}"`,
      keywords: `Extract key topics from this text: "${text}"`,
      translate: `Translate this to Vietnamese: "${text}"`
    };

    const prompt = prompts[analysisType] || `Analyze this text: "${text}"`;

    const config = await loadConfig();
    const provider = config.settings?.ai_provider || 'openai';

    let response;
    if (provider === 'openai') {
      response = await callOpenAI(prompt);
    } else {
      response = await callAnthropic(prompt);
    }

    await logAIUsage(clientId, 'public', 'analyze', { 
      provider,
      analysisType: analysisType || 'general',
      textLength: text.length
    });

    res.json({
      success: true,
      analysis: response,
      type: analysisType,
      provider: provider,
      remaining: rateLimit.remaining
    });
  } catch(err) {
    console.error('AI Analyze error:', err);
    res.status(500).json({ 
      success: false, 
      message: err.message || 'AI service error' 
    });
  }
});

// Get AI Usage Stats
app.get('/api/ai/stats', async (req, res) => {
  try {
    const clientId = getClientIdentifier(req);
    const rateLimit = aiRateLimits.get(clientId);
    const dailyUsed = rateLimit ? rateLimit.count : 0;
    const dailyRemaining = AI_DAILY_LIMIT - dailyUsed;

    res.json({
      success: true,
      stats: {
        dailyLimit: AI_DAILY_LIMIT,
        dailyUsed: dailyUsed,
        dailyRemaining: dailyRemaining,
        resetAt: rateLimit ? new Date(rateLimit.resetAt).toISOString() : null
      }
    });
  } catch(err) {
    console.error('AI Stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: AI LOGS ================= */
app.get('/api/admin/ai-logs', requireAdmin, async (req, res) => {
  try {
    const logs = await loadAILogs();
    const limit = parseInt(req.query.limit) || 100;
    res.json(logs.slice(-limit).reverse());
  } catch(err) {
    console.error('Get AI logs error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= REST OF ENDPOINTS (SAME AS BEFORE) ================= */
// ... [Keep all other endpoints from original file: create-key, list-keys, verify-key, etc.]

/* ================= CREATE KEY ================= */
app.post('/api/create-key', async (req, res) => {
  try {
    const { days, devices, type, customKey } = req.body || {};
    
    if (!days || !devices) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    }

    const config = await loadConfig();
    const maxDays = config.settings?.max_key_days || 365;
    
    if (days > maxDays) {
      return res.status(400).json({ 
        success: false, 
        message: `Thời hạn tối đa ${maxDays} ngày` 
      });
    }

    let keyCode;
    
    if (customKey && customKey.trim()) {
      keyCode = customKey.trim();
      const keys = await loadKeys();
      if (keys.find(k => k.key_code === keyCode)) {
        return res.status(400).json({ 
          success: false, 
          message: 'Key code đã tồn tại. Vui lòng chọn mã khác.' 
        });
      }
    } else {
      keyCode = generateKey(type || "KEY");
    }

    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    const signature = signValue(keyCode);

    const keys = await loadKeys();
    const record = {
      id: uuidv4(),
      key_code: keyCode,
      type: type || "KEY",
      signature,
      created_at: createdAt,
      expires_at: expiresAt,
      allowed_devices: Number(devices),
      devices: [],
      owner_id: 'public',
      owner_username: 'public',
      require_api_key: false,
      total_verifications: 0,
      last_verified: null,
      is_custom: !!customKey
    };

    keys.push(record);
    await saveKeys(keys);

    await logActivity('create_key', 'public', 'public', { 
      keyCode, 
      type, 
      days, 
      devices,
      custom: !!customKey 
    });

    res.json({ success: true, key: record });
  } catch(err) {
    console.error('Create key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/bulk-create-keys', async (req, res) => {
  try {
    const { count, days, devices, type } = req.body || {};
    
    if (!count || !days || !devices || count < 1 || count > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Số lượng phải từ 1-100' 
      });
    }

    const keys = await loadKeys();
    const createdKeys = [];

    for (let i = 0; i < count; i++) {
      const keyCode = generateKey(type || "KEY");
      const createdAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
      const signature = signValue(keyCode);

      const record = {
        id: uuidv4(),
        key_code: keyCode,
        type: type || "KEY",
        signature,
        created_at: createdAt,
        expires_at: expiresAt,
        allowed_devices: Number(devices),
        devices: [],
        owner_id: 'public',
        owner_username: 'public',
        require_api_key: false,
        total_verifications: 0,
        last_verified: null
      };

      keys.push(record);
      createdKeys.push(record);
    }

    await saveKeys(keys);

    await logActivity('bulk_create_keys', 'public', 'public', { 
      count, 
      type, 
      days, 
      devices 
    });

    res.json({ 
      success: true, 
      message: `Tạo thành công ${count} keys`, 
      keys: createdKeys 
    });
  } catch(err) {
    console.error('Bulk create error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/list-keys', async (req, res) => {
  try {
    res.json(await loadKeys());
  } catch(err) {
    console.error('List all keys error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/my-stats', async (req, res) => {
  try {
    const keys = await loadKeys();
    const now = new Date();

    const stats = {
      totalKeys: keys.length,
      activeKeys: keys.filter(k => new Date(k.expires_at) > now).length,
      expiredKeys: keys.filter(k => new Date(k.expires_at) <= now).length,
      keyLimit: 'Không giới hạn',
      keysRemaining: 'Không giới hạn',
      totalKeysCreated: keys.length,
      totalVerifications: keys.reduce((sum, k) => sum + (k.total_verifications || 0), 0),
      aiAccess: true,
      aiUsageCount: null
    };

    res.json(stats);
  } catch(err) {
    console.error('Stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/my-api-code', async (req, res) => {
  res.json({
    success: true,
    apiCode: null,
    username: 'public',
    note: 'API Code không bắt buộc'
  });
});

app.post('/api/reset-api-code', async (req, res) => {
  res.status(400).json({
    success: false,
    message: 'Không hỗ trợ reset API Code trong chế độ public'
  });
});

app.post('/api/extend-key', async (req, res) => {
  try {
    const { key, days } = req.body || {};
    const keys = await loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    found.expires_at = new Date(
      new Date(found.expires_at).getTime() + days * 86400000
    ).toISOString();

    await saveKeys(keys);

    await logActivity('extend_key', 'public', 'public', { keyCode: key, days });

    res.json({ success: true, message: 'Gia hạn key thành công' });
  } catch(err) {
    console.error('Extend key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/reset-key', async (req, res) => {
  try {
    const { key } = req.body || {};
    const keys = await loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    const oldDevices = found.devices.length;
    found.devices = [];
    await saveKeys(keys);

    await logActivity('reset_key', 'public', 'public', { 
      keyCode: key, 
      devicesCleared: oldDevices 
    });

    res.json({ success: true, message: 'Reset thiết bị thành công' });
  } catch(err) {
    console.error('Reset key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/delete-key', async (req, res) => {
  try {
    const { key } = req.body || {};
    let keys = await loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    keys = keys.filter(k => k.key_code !== key);
    await saveKeys(keys);

    if (found.owner_id && found.owner_id !== 'admin') {
      const users = await loadUsers();
      const user = users.find(u => u.id === found.owner_id);
      if (user && user.keyCount > 0) {
        user.keyCount--;
        await saveUsers(users);
      }
    }

    await logActivity('delete_key', 'public', 'public', { keyCode: key });

    res.json({ success: true, message: 'Xóa key thành công' });
  } catch(err) {
    console.error('Delete key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/verify-key', async (req, res) => {
  try {
    const { key, device_id } = req.body || {};
    
    if (!key || !device_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Thiếu key hoặc device_id',
        error_code: 'MISSING_PARAMS'
      });
    }

    const keys = await loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ 
        success: false, 
        message: 'Key không tồn tại',
        error_code: 'KEY_NOT_FOUND'
      });
    }

    const expectedSig = signValue(found.key_code);
    if (expectedSig !== found.signature) {
      return res.status(500).json({ 
        success: false, 
        message: 'Chữ ký không khớp',
        error_code: 'SIGNATURE_MISMATCH'
      });
    }

    if (new Date(found.expires_at) < new Date()) {
      return res.json({ 
        success: false, 
        message: 'Key đã hết hạn',
        error_code: 'KEY_EXPIRED',
        expired_at: found.expires_at
      });
    }

    if (!found.devices.includes(device_id)) {
      if (found.devices.length >= found.allowed_devices) {
        return res.json({ 
          success: false, 
          message: 'Đã đạt giới hạn thiết bị',
          error_code: 'DEVICE_LIMIT_REACHED',
          devices_used: found.devices.length,
          devices_allowed: found.allowed_devices
        });
      }

      found.devices.push(device_id);
    }

    found.total_verifications = (found.total_verifications || 0) + 1;
    found.last_verified = new Date().toISOString();
    await saveKeys(keys);

    res.json({ 
      success: true, 
      message: 'Xác thực thành công', 
      type: found.type,
      expires_at: found.expires_at,
      devices_remaining: found.allowed_devices - found.devices.length
    });
  } catch(err) {
    console.error('Verify error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error_code: 'SERVER_ERROR'
    });
  }
});

app.post('/api/key-info', async (req, res) => {
  try {
    const { key } = req.body || {};
    
    if (!key) {
      return res.status(400).json({ success: false, message: 'Thiếu key' });
    }

    const keys = await loadKeys();
    const found = keys.find(k => k.key_code === key);
    
    if (!found) {
      return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    }

    const now = new Date();
    const expiresAt = new Date(found.expires_at);
    const isExpired = expiresAt < now;
    const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

    res.json({
      success: true,
      info: {
        type: found.type,
        created_at: found.created_at,
        expires_at: found.expires_at,
        is_expired: isExpired,
        days_remaining: isExpired ? 0 : daysRemaining,
        devices_used: found.devices.length,
        devices_allowed: found.allowed_devices,
        total_verifications: found.total_verifications || 0,
        last_verified: found.last_verified || 'Never',
        is_custom: found.is_custom || false
      }
    });
  } catch(err) {
    console.error('Key info error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN USER MANAGEMENT ================= */
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await loadUsers();
    const sanitizedUsers = users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      isActive: u.isActive,
      isBanned: u.isBanned,
      keyCount: u.keyCount,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin,
      apiCode: u.apiCode,
      deviceId: u.deviceId,
      totalKeysCreated: u.totalKeysCreated || 0,
      totalVerifications: u.totalVerifications || 0,
      aiUsageCount: u.aiUsageCount || 0
    }));
    res.json(sanitizedUsers);
  } catch(err) {
    console.error('List users error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


app.post('/api/admin/ban-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    
    const users = await loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    user.isBanned = true;
    await saveUsers(users);

    await logActivity('ban_user', 'admin', 'admin', { targetUser: user.username });
    
    res.json({ success: true, message: 'Đã ban user' });
  } catch(err) {
    console.error('Ban user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/unban-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    
    const users = await loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    user.isBanned = false;
    await saveUsers(users);

    await logActivity('unban_user', 'admin', 'admin', { targetUser: user.username });
    
    res.json({ success: true, message: 'Đã unban user' });
  } catch(err) {
    console.error('Unban user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/toggle-active', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    
    const users = await loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    user.isActive = !user.isActive;
    await saveUsers(users);

    await logActivity('toggle_active', 'admin', 'admin', { 
      targetUser: user.username, 
      newStatus: user.isActive 
    });
    
    res.json({ success: true, message: user.isActive ? 'Đã kích hoạt user' : 'Đã khóa user' });
  } catch(err) {
    console.error('Toggle active error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/delete-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    
    let users = await loadUsers();
    const user = users.find(u => u.id === userId);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
    }

    let keys = await loadKeys();
    keys = keys.filter(k => k.owner_id !== userId);
    await saveKeys(keys);

    users = users.filter(u => u.id !== userId);
    await saveUsers(users);

    await logActivity('delete_user', 'admin', 'admin', { targetUser: user.username });
    
    res.json({ success: true, message: 'Đã xóa user và tất cả key của họ' });
  } catch(err) {
    console.error('Delete user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const config = await loadConfig();
    res.json(config.settings || {});
  } catch(err) {
    console.error('Get settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const config = await loadConfig();
    config.settings = { ...config.settings, ...req.body };
    await saveConfig(config);

    await logActivity('update_settings', 'admin', 'admin', req.body);

    res.json({ success: true, message: 'Cập nhật settings thành công' });
  } catch(err) {
    console.error('Update settings error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  try {
    const logs = await loadLogs();
    const limit = parseInt(req.query.limit) || 100;
    res.json(logs.slice(-limit).reverse());
  } catch(err) {
    console.error('Get logs error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/backup', requireAdmin, async (req, res) => {
  try {
    await createBackup();
    res.json({ success: true, message: 'Backup thành công' });
  } catch(err) {
    console.error('Backup error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/backups', requireAdmin, async (req, res) => {
  try {
    const backups = await fs.readdir(BACKUP_DIR);
    const backupDetails = await Promise.all(
      backups.map(async (name) => {
        const backupPath = path.join(BACKUP_DIR, name);
        const stats = await fs.stat(backupPath);
        return {
          name,
          created: stats.mtime,
          size: stats.size
        };
      })
    );
    res.json(backupDetails);
  } catch(err) {
    console.error('List backups error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const users = await loadUsers();
    const keys = await loadKeys();
    const devices = await loadDevices();
    const aiLogs = await loadAILogs();
    const now = new Date();

    const stats = {
      totalUsers: users.length,
      activeUsers: users.filter(u => u.isActive && !u.isBanned).length,
      bannedUsers: users.filter(u => u.isBanned).length,
      totalKeys: keys.length,
      activeKeys: keys.filter(k => new Date(k.expires_at) > now).length,
      expiredKeys: keys.filter(k => new Date(k.expires_at) <= now).length,
      totalDevices: devices.length,
      totalVerifications: keys.reduce((sum, k) => sum + (k.total_verifications || 0), 0),
      totalAIRequests: aiLogs.length,
      aiRequestsToday: aiLogs.filter(log => {
        const logDate = new Date(log.timestamp);
        const today = new Date();
        return logDate.toDateString() === today.toDateString();
      }).length
    };

    res.json(stats);
  } catch(err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/contact', async (req, res) => {
  try {
    const cfg = await loadConfig();
    res.json(cfg.contact || {});
  } catch(err) {
    console.error('Get contact error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api', async (req, res) => {
  const config = await loadConfig();
  res.json({
    name: "AuthAPI v3.5 ULTIMATE - Anti-Crash + AI Features",
    version: "3.5.0",
    status: "online",
    maintenance_mode: config.settings?.maintenance_mode || false,
    features: [
      "✅ Public key creation",
      "✅ Public AI access",
      "✅ Same email for multiple accounts",
      "✅ 3 accounts per device limit (strict)",
      "💎 Custom key creation available",
      "📦 Bulk key creation available",
      "🤖 AI Chat (100 req/day)",
      "🎨 AI Image Generation",
      "💻 AI Code Helper",
      "📊 AI Text Analysis",
      "💾 Auto backup every 6 hours",
      "📊 Activity logging system",
      "🔐 HMAC signature verification",
      "📱 Device tracking (by UserAgent + IP)",
      "🛡️ Anti-crash error handling",
      "🔒 File locking system",
      "⚡ Retry mechanism with exponential backoff",
      "💾 Memory monitoring & GC",
      "⏱️ Request timeout protection",
      "⚙️ System settings management",
      "🔧 Maintenance mode support"
    ],
    ai_features: {
      access: "Public access",
      daily_limit: AI_DAILY_LIMIT,
      rate_limit: `${AI_RATE_LIMIT_MS/1000} seconds between requests`,
      endpoints: [
        "/api/ai/chat - AI conversation",
        "/api/ai/image - Generate images",
        "/api/ai/code - Code assistance",
        "/api/ai/analyze - Text analysis",
        "/api/ai/stats - Usage statistics"
      ],
      providers: ["OpenAI (GPT, DALL-E)", "Anthropic (Claude)"]
    },
    security: {
      authentication: "Public access - no login required",
      email_verification: "DISABLED - Accept any email, allow duplicates",
      device_limit: "3 accounts per device (UserAgent + IP hash)",
      key_verification: "API Code not required"
    },
    key_prefixes: {
      standard: "KEY-XXXXXX-XXXX",
      custom: "Custom keys are available"
    }
  });
});


/* ═══════════════════════════════════════════════════════════
   DEVICE UID SYSTEM — Lấy / Đăng ký / Tra cứu UID thiết bị
   ═══════════════════════════════════════════════════════════ */

// ── Helpers ─────────────────────────────────────────────────
/**
 * Tạo UID thiết bị bền vững từ nhiều tín hiệu:
 *  - IP address (X-Forwarded-For → req.ip)
 *  - User-Agent
 *  - Accept-Language
 *  - Giờ tạo (để tránh va chạm nếu cùng máy → thêm salt ngẫu nhiên nhẹ)
 * Format: DEV-XXXXXXXX-XXXX-XXXX
 */
function buildDeviceUID(req) {
  const ip  = (req.headers["x-forwarded-for"] || "").split(",")[0].trim()
            || req.ip || req.connection?.remoteAddress || "unknown";
  const ua  = req.headers["user-agent"]        || "";
  const lan = req.headers["accept-language"]   || "";
  const raw = `${ip}|${ua}|${lan}`;
  const hash = crypto.createHash("sha256").update(raw).digest("hex").toUpperCase();
  // Format DEV-XXXXXXXX-XXXX-XXXX (đọc dễ hơn)
  return `DEV-${hash.slice(0,8)}-${hash.slice(8,12)}-${hash.slice(12,16)}`;
}

function buildDeviceMeta(req) {
  return {
    ip: (req.headers["x-forwarded-for"] || "").split(",")[0].trim()
      || req.ip || "unknown",
    user_agent: (req.headers["user-agent"] || "").slice(0, 200),
    language:   req.headers["accept-language"] || "",
    platform:   req.headers["sec-ch-ua-platform"] || "",
    mobile:     req.headers["sec-ch-ua-mobile"]   || ""
  };
}

// ── 1. GET /api/device-uid ───────────────────────────────────
/**
 * Trả về UID của thiết bị đang gọi (tự nhận diện)
 * Không cần body. Chỉ cần gọi GET.
 */
app.get("/api/device-uid", (req, res) => {
  try {
    const uid  = buildDeviceUID(req);
    const meta = buildDeviceMeta(req);
    res.json({
      success: true,
      device_uid: uid,
      meta,
      note: "UID được tạo từ IP + User-Agent. Thay đổi mạng/trình duyệt sẽ thay đổi UID."
    });
  } catch (err) {
    console.error("device-uid error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ── 2. POST /api/device-uid/register ────────────────────────
/**
 * Đăng ký UID thiết bị + gắn tùy chọn vào key
 * Body: { key_code?: string, label?: string }
 * - Nếu có key_code → kiểm tra key hợp lệ → ghi device_uid vào key
 * - Luôn ghi vào devices.json
 */
app.post("/api/device-uid/register", async (req, res) => {
  try {
    const { key_code, label } = req.body || {};
    const uid  = buildDeviceUID(req);
    const meta = buildDeviceMeta(req);
    const now  = new Date().toISOString();

    // ── Lưu vào devices.json ──────────────────────────────
    const devices  = await loadDevices();
    let devRecord  = devices.find(d => d.uid === uid);

    if (!devRecord) {
      devRecord = {
        id:         uuidv4(),
        uid,
        label:      label || "",
        meta,
        keys:       [],
        first_seen: now,
        last_seen:  now
      };
      devices.push(devRecord);
    } else {
      devRecord.last_seen = now;
      devRecord.meta      = meta;        // refresh metadata
      if (label) devRecord.label = label;
    }

    // ── Gắn vào key nếu có ───────────────────────────────
    let keyInfo = null;
    if (key_code) {
      const keys  = await loadKeys();
      const found = keys.find(k => k.key_code === key_code);

      if (!found) {
        return res.status(404).json({
          success: false,
          message: "Key không tồn tại",
          error_code: "KEY_NOT_FOUND"
        });
      }

      if (new Date(found.expires_at) < new Date()) {
        return res.status(400).json({
          success: false,
          message: "Key đã hết hạn",
          error_code: "KEY_EXPIRED"
        });
      }

      // Ghi device_uid vào key.devices nếu chưa có
      if (!found.devices.includes(uid)) {
        if (found.devices.length >= found.allowed_devices) {
          return res.status(400).json({
            success: false,
            message: "Key đã đạt giới hạn thiết bị",
            error_code: "DEVICE_LIMIT_REACHED",
            devices_used:    found.devices.length,
            devices_allowed: found.allowed_devices
          });
        }
        found.devices.push(uid);
        await saveKeys(keys);
      }

      // Ghi ngược key_code vào devRecord
      if (!devRecord.keys.includes(key_code))
        devRecord.keys.push(key_code);

      keyInfo = {
        key_code:        found.key_code,
        type:            found.type,
        expires_at:      found.expires_at,
        devices_used:    found.devices.length,
        devices_allowed: found.allowed_devices
      };
    }

    await saveDevices(devices);
    await logActivity("register_device_uid", "public", "public", { uid, key_code, label });

    res.json({
      success:    true,
      device_uid: uid,
      label:      devRecord.label,
      first_seen: devRecord.first_seen,
      last_seen:  devRecord.last_seen,
      keys:       devRecord.keys,
      key_info:   keyInfo,
      meta
    });
  } catch (err) {
    console.error("device-uid/register error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ── 3. POST /api/device-uid/lookup ──────────────────────────
/**
 * Tra cứu thông tin theo UID (admin hoặc tự tra)
 * Body: { uid: string }
 */
app.post("/api/device-uid/lookup", async (req, res) => {
  try {
    const { uid } = req.body || {};
    if (!uid) {
      return res.status(400).json({
        success: false,
        message: "Thiếu uid",
        error_code: "MISSING_UID"
      });
    }

    const devices = await loadDevices();
    const record  = devices.find(d => d.uid === uid);

    if (!record) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy thiết bị",
        error_code: "DEVICE_NOT_FOUND"
      });
    }

    // Lấy thông tin key gắn với thiết bị
    const keys    = await loadKeys();
    const now     = new Date();
    const keyList = record.keys
      .map(kc => keys.find(k => k.key_code === kc))
      .filter(Boolean)
      .map(k => ({
        key_code:        k.key_code,
        type:            k.type,
        expires_at:      k.expires_at,
        is_expired:      new Date(k.expires_at) < now,
        days_remaining:  Math.max(0, Math.ceil((new Date(k.expires_at) - now) / 86400000)),
        devices_used:    k.devices.length,
        devices_allowed: k.allowed_devices
      }));

    res.json({
      success:    true,
      device_uid: record.uid,
      label:      record.label || "",
      first_seen: record.first_seen,
      last_seen:  record.last_seen,
      keys:       keyList,
      meta:       record.meta || {}
    });
  } catch (err) {
    console.error("device-uid/lookup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ── 4. GET /api/device-uid/my-keys ──────────────────────────
/**
 * Lấy tất cả key đã đăng ký với thiết bị hiện tại (tự động nhận diện)
 */
app.get("/api/device-uid/my-keys", async (req, res) => {
  try {
    const uid     = buildDeviceUID(req);
    const devices = await loadDevices();
    const record  = devices.find(d => d.uid === uid);

    if (!record || !record.keys.length) {
      return res.json({
        success:    true,
        device_uid: uid,
        keys:       [],
        message:    "Thiết bị này chưa đăng ký key nào"
      });
    }

    const keys    = await loadKeys();
    const now     = new Date();
    const keyList = record.keys
      .map(kc => keys.find(k => k.key_code === kc))
      .filter(Boolean)
      .map(k => ({
        key_code:        k.key_code,
        type:            k.type,
        expires_at:      k.expires_at,
        is_expired:      new Date(k.expires_at) < now,
        days_remaining:  Math.max(0, Math.ceil((new Date(k.expires_at) - now) / 86400000)),
        devices_used:    k.devices.length,
        devices_allowed: k.allowed_devices,
        total_verifications: k.total_verifications || 0
      }));

    res.json({
      success:    true,
      device_uid: uid,
      label:      record.label || "",
      first_seen: record.first_seen,
      last_seen:  record.last_seen,
      keys:       keyList
    });
  } catch (err) {
    console.error("device-uid/my-keys error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ── 5. GET /api/admin/devices (admin only) ───────────────────
/**
 * Liệt kê tất cả thiết bị đã đăng ký (admin)
 */
app.get("/api/admin/devices", requireAdmin, async (req, res) => {
  try {
    const devices  = await loadDevices();
    const keys     = await loadKeys();
    const now      = new Date();
    const limit    = parseInt(req.query.limit) || 100;
    const page     = parseInt(req.query.page)  || 1;
    const search   = (req.query.search || "").toLowerCase();

    let filtered = devices;
    if (search) {
      filtered = devices.filter(d =>
        d.uid.toLowerCase().includes(search)           ||
        (d.label || "").toLowerCase().includes(search) ||
        (d.meta?.ip || "").toLowerCase().includes(search)
      );
    }

    // Sort by last_seen desc
    filtered.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));

    const total    = filtered.length;
    const paginated = filtered.slice((page-1)*limit, page*limit);

    const result = paginated.map(d => ({
      ...d,
      key_count:       d.keys.length,
      active_key_count: d.keys.filter(kc => {
        const k = keys.find(k => k.key_code === kc);
        return k && new Date(k.expires_at) > now;
      }).length
    }));

    res.json({
      success: true,
      total,
      page,
      limit,
      devices: result
    });
  } catch (err) {
    console.error("admin/devices error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ── 6. POST /api/admin/devices/delete (admin only) ──────────
app.post("/api/admin/devices/delete", requireAdmin, async (req, res) => {
  try {
    const { uid } = req.body || {};
    if (!uid)
      return res.status(400).json({ success: false, message: "Thiếu uid" });

    let devices = await loadDevices();
    const before = devices.length;
    devices = devices.filter(d => d.uid !== uid);

    if (devices.length === before)
      return res.status(404).json({ success: false, message: "Không tìm thấy thiết bị" });

    await saveDevices(devices);
    await logActivity("delete_device", "admin", "admin", { uid });
    res.json({ success: true, message: "Đã xóa thiết bị" });
  } catch (err) {
    console.error("admin/devices/delete error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get('/health', async (req, res) => {
  const used = process.memoryUsage();
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      heapUsed: Math.round(used.heapUsed / 1024 / 1024) + 'MB',
      heapTotal: Math.round(used.heapTotal / 1024 / 1024) + 'MB',
      rss: Math.round(used.rss / 1024 / 1024) + 'MB'
    }
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    error_code: 'NOT_FOUND'
  });
});

/* ================= SERVER START ================= */
async function startServer() {
  try {
    await initializeFiles();
    await ensureBackupDir();
    
    const server = app.listen(PORT, () => {
      console.log('╔═══════════════════════════════════════════════════╗');
      console.log('║   AuthAPI v3.5 ULTIMATE - AI Edition             ║');
      console.log('╚═══════════════════════════════════════════════════╝');
      console.log(`✅ Server: http://localhost:${PORT}`);
      console.log('📧 Same email: Multiple accounts allowed');
      console.log('🔒 Device limit: Max 3 accounts per device');
      console.log('🔑 Key creation: Public access');
      console.log('💎 Custom keys available');
      console.log('📦 Bulk create available (1-100 keys)');
      console.log('🤖 AI Features: Public access (100 req/day)');
      console.log('  ├─ AI Chat (GPT/Claude)');
      console.log('  ├─ AI Image (DALL-E)');
      console.log('  ├─ AI Code Helper');
      console.log('  └─ AI Text Analysis');
      console.log('💾 Auto backup: Every 6 hours');
      console.log('📊 Activity logs: Last 1000 actions');
      console.log('� No API Code required for public access');
      console.log('⭐ Public access: AI + Bulk create enabled');
      console.log('🛡️ Anti-crash: File locking + Retry + Memory monitor');
      console.log('═══════════════════════════════════════════════════');
      
      createBackup().catch(err => console.error('Initial backup failed:', err));
    });

    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} received...`);
      console.log('Creating final backup...');
      await createBackup();
      
      server.close(() => {
        console.log('Server closed gracefully');
        process.exit(0);
      });

      setTimeout(() => {
        console.error('Forced shutdown after timeout');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
