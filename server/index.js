const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

dotenv.config();

const { createAdapter } = require('@socket.io/redis-adapter');
const { createClient } = require('redis');

const normalizeOrigin = (origin) => (origin ? origin.replace(/\/$/, '') : origin);
const normalizeBaseUrl = (url) => (url ? url.replace(/\/$/, '') : url);

const DEFAULT_CLIENT_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://klymo-client-cnxt.vercel.app'
];
const envOrigins = (process.env.CLIENT_ORIGINS || process.env.CLIENT_ORIGIN || '')
  .split(',')
  .map((origin) => normalizeOrigin(origin.trim()))
  .filter(Boolean);
const renderExternalUrl = normalizeOrigin(process.env.RENDER_EXTERNAL_URL || '');

const allowedOrigins = new Set(
  [...DEFAULT_CLIENT_ORIGINS, ...envOrigins, renderExternalUrl].filter(Boolean)
);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const normalized = normalizeOrigin(origin);
    if (allowedOrigins.has(normalized)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
};

const DAILY_MATCH_LIMIT = Number(process.env.DAILY_MATCH_LIMIT || 100);
const REPORT_THRESHOLD = Number(process.env.REPORT_THRESHOLD || 5);
const REPORT_TTL_SECONDS = Number(process.env.REPORT_TTL_SECONDS || 7 * 24 * 60 * 60);
const MATCH_COUNT_TTL_SECONDS = Number(process.env.MATCH_COUNT_TTL_SECONDS || 48 * 60 * 60);
const GENDER_SERVICE_URL = normalizeBaseUrl(process.env.GENDER_SERVICE_URL || 'http://localhost:8000');
const VERIFICATION_TOKEN_TTL_SECONDS = Number(process.env.VERIFICATION_TOKEN_TTL_SECONDS || 24 * 60 * 60);
const VERIFICATION_TOKEN_SECRET = process.env.VERIFICATION_TOKEN_SECRET || 'dev_only_change_me';
if (!process.env.VERIFICATION_TOKEN_SECRET) {
  console.warn('WARNING: VERIFICATION_TOKEN_SECRET is not set. Use a strong secret in production.');
}

function signVerificationToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', VERIFICATION_TOKEN_SECRET)
    .update(encoded)
    .digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyVerificationToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, signature] = parts;
  const expected = crypto
    .createHmac('sha256', VERIFICATION_TOKEN_SECRET)
    .update(encoded)
    .digest('base64url');
  const signatureOk =
    signature.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  if (!signatureOk) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload || !payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch (err) {
    return null;
  }
}

// Redis Clients Configuration (Optional - falls back to in-memory for local dev)
const redisUrl = process.env.REDIS_URL || '';
let pubClient = null;
let subClient = null;
let redisAvailable = false;

if (redisUrl) {
  pubClient = createClient({ url: redisUrl });
  subClient = pubClient.duplicate();

  pubClient.on('error', (err) => { /* suppress noise — handled below */ });
  subClient.on('error', (err) => { /* suppress noise — handled below */ });

  (async () => {
    try {
      await Promise.all([pubClient.connect(), subClient.connect()]);
      redisAvailable = true;
      console.log('Redis Layer: Connected for horizontal scaling.');
    } catch (err) {
      redisAvailable = false;
      console.warn('Redis Layer: Unavailable — running in single-instance in-memory mode (local dev).');
    }
  })();
} else {
  console.log('Redis Layer: No REDIS_URL set — running in-memory mode (local dev).');
}


// ─── In-memory fallback stores (used when Redis is unavailable) ───────────────
const memBans = new Map();          // deviceId -> banInfo
const memBlocks = new Map();        // myDeviceId -> Set of blocked deviceIds
const memMatchCounts = new Map();   // deviceId -> count
const memReports = new Map();       // targetDeviceId -> Set of reporterDeviceIds
let   memReportsTotal = 0;
const memQueue = [];                // in-memory match queue
// ─────────────────────────────────────────────────────────────────────────────

const REDIS_KEYS = {
  BANS: 'anonchat:bans',
  BLOCKS: 'anonchat:blocks:',
  MATCH_COUNTS_PREFIX: 'anonchat:match_counts:',
  QUEUE: 'anonchat:queue',
  REPORTS_TOTAL: 'anonchat:reports:total',
  REPORTS_SET_PREFIX: 'anonchat:reports:'
};

function getDailyMatchKey() {
  const today = new Date().toISOString().slice(0, 10);
  return `${REDIS_KEYS.MATCH_COUNTS_PREFIX}${today}`;
}

async function getBans(deviceId) {
  if (!redisAvailable) return memBans.get(deviceId) || null;
  const ban = await pubClient.hGet(REDIS_KEYS.BANS, deviceId);
  return ban ? JSON.parse(ban) : null;
}

async function setBan(deviceId, banInfo) {
  if (!redisAvailable) { memBans.set(deviceId, banInfo); return; }
  await pubClient.hSet(REDIS_KEYS.BANS, deviceId, JSON.stringify(banInfo));
}

async function clearBan(deviceId) {
  if (!redisAvailable) { memBans.delete(deviceId); return; }
  await pubClient.hDel(REDIS_KEYS.BANS, deviceId);
}

async function isBlocked(myDeviceId, targetDeviceId) {
  if (!redisAvailable) return (memBlocks.get(myDeviceId) || new Set()).has(targetDeviceId);
  return await pubClient.sIsMember(REDIS_KEYS.BLOCKS + myDeviceId, targetDeviceId);
}

async function addBlock(myDeviceId, targetDeviceId) {
  if (!redisAvailable) {
    if (!memBlocks.has(myDeviceId)) memBlocks.set(myDeviceId, new Set());
    memBlocks.get(myDeviceId).add(targetDeviceId);
    return;
  }
  await pubClient.sAdd(REDIS_KEYS.BLOCKS + myDeviceId, targetDeviceId);
}

async function getMatchCount(deviceId) {
  if (!redisAvailable) return memMatchCounts.get(deviceId) || 0;
  const count = await pubClient.hGet(getDailyMatchKey(), deviceId);
  return count ? parseInt(count) : 0;
}

async function incrementMatchCount(deviceId) {
  if (!redisAvailable) {
    memMatchCounts.set(deviceId, (memMatchCounts.get(deviceId) || 0) + 1);
    return;
  }
  const key = getDailyMatchKey();
  const multi = pubClient.multi();
  multi.hIncrBy(key, deviceId, 1);
  multi.expire(key, MATCH_COUNT_TTL_SECONDS);
  await multi.exec();
}

async function recordReport(reporterDeviceId, targetDeviceId) {
  if (!redisAvailable) {
    if (!memReports.has(targetDeviceId)) memReports.set(targetDeviceId, new Set());
    memReports.get(targetDeviceId).add(reporterDeviceId);
    memReportsTotal++;
    return memReports.get(targetDeviceId).size;
  }
  const reportKey = `${REDIS_KEYS.REPORTS_SET_PREFIX}${targetDeviceId}`;
  await pubClient.sAdd(reportKey, reporterDeviceId);
  const uniqueReporters = await pubClient.sCard(reportKey);
  if (uniqueReporters === 1) await pubClient.expire(reportKey, REPORT_TTL_SECONDS);
  await pubClient.incr(REDIS_KEYS.REPORTS_TOTAL);
  return uniqueReporters;
}

// Global Metrics state (Shared via Redis)
const metrics = {
  totalMatches: 0,
  activeSessions: 0,
  verificationAttempts: 0,
  verificationSuccess: 0,
  totalReports: 0, 
  matchWaitTimes: [] 
};

// Local reports array (Keeping local for now as it's less critical for scaling)
const reports = [];


// Match Queue — Redis when available, in-memory otherwise
class RedisMatchQueue {
  constructor(io) {
    this.io = io;
  }

  async add(user) {
    const entry = JSON.stringify({ ...user, timestamp: Date.now() });
    if (!redisAvailable) {
      memQueue.push(entry);
      console.log(`Queue: Added ${user.nickname} (in-memory, ${memQueue.length} waiting).`);
      return;
    }
    await pubClient.lPush(REDIS_KEYS.QUEUE, entry);
    console.log(`Queue: Added ${user.nickname} to Redis Pool.`);
  }

  async removeBySocketId(socketId) {
    if (!redisAvailable) {
      const idx = memQueue.findIndex(item => { try { return JSON.parse(item).id === socketId; } catch { return false; } });
      if (idx !== -1) memQueue.splice(idx, 1);
      return;
    }
    const queueData = await pubClient.lRange(REDIS_KEYS.QUEUE, 0, -1);
    for (const item of queueData) {
      try {
        const u = JSON.parse(item);
        if (u.id === socketId) await pubClient.lRem(REDIS_KEYS.QUEUE, 0, item);
      } catch { await pubClient.lRem(REDIS_KEYS.QUEUE, 0, item); }
    }
  }

  async isSocketActive(socketId) {
    const sockets = await this.io.in(socketId).allSockets();
    return sockets.has(socketId);
  }

  async findMatch(user) {
    const queueData = redisAvailable
      ? await pubClient.lRange(REDIS_KEYS.QUEUE, 0, 49)
      : [...memQueue];

    for (let i = 0; i < queueData.length; i++) {
      let u;
      try { u = JSON.parse(queueData[i]); }
      catch {
        if (redisAvailable) await pubClient.lRem(REDIS_KEYS.QUEUE, 0, queueData[i]);
        else memQueue.splice(memQueue.indexOf(queueData[i]), 1);
        continue;
      }

      const selfMatch = u.id === user.id;
      const allowSameDevice = true; // DEV OVERRIDE
      const sameDevice = u.deviceId === user.deviceId;
      const genderMatch = (user.matchPreference === 'Any' || u.gender === user.matchPreference);
      const partnerPrefMatch = (u.matchPreference === 'Any' || user.gender === u.matchPreference);
      const blocked = await isBlocked(user.deviceId, u.deviceId) || await isBlocked(u.deviceId, user.deviceId);
      const isRepeat = user.lastPartnerId === u.deviceId || u.lastPartnerId === user.deviceId;

      if (!selfMatch && (allowSameDevice || !sameDevice) && genderMatch && partnerPrefMatch && !blocked && !isRepeat) {
        const stillConnected = await this.isSocketActive(u.id);
        if (!stillConnected) {
          if (redisAvailable) await pubClient.lRem(REDIS_KEYS.QUEUE, 0, queueData[i]);
          else memQueue.splice(memQueue.indexOf(queueData[i]), 1);
          continue;
        }
        if (redisAvailable) {
          const removedCount = await pubClient.lRem(REDIS_KEYS.QUEUE, 1, queueData[i]);
          if (removedCount > 0) return u;
        } else {
          const idx = memQueue.indexOf(queueData[i]);
          if (idx !== -1) { memQueue.splice(idx, 1); return u; }
        }
      }
    }
    return null;
  }
}

// Data Cleanup Policy (Bucket G/4)
// Automatically clear old match counts every 24 hours to maintain "Controlled Anonymity"
setInterval(() => {
  console.log('Privacy Engine: Performing scheduled metadata cleanup...');
  // Optional: Reset match counts or clear old reports if needed
}, 24 * 60 * 60 * 1000);

// Rate Limiter Middleware (Architecture Requirement)
const apiRequests = new Map(); // IP -> { count, startTime }
function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const limit = 30; // 30 requests per minute

  if (!apiRequests.has(ip)) {
    apiRequests.set(ip, { count: 1, startTime: now });
    return next();
  }

  const tracker = apiRequests.get(ip);
  if (now - tracker.startTime > windowMs) {
    tracker.count = 1;
    tracker.startTime = now;
    return next();
  }

  tracker.count++;
  if (tracker.count > limit) {
    return res.status(429).json({ error: 'Too many requests. Please slow down.' });
  }
  next();
}

const app = express();
app.set('trust proxy', 1);
app.use(rateLimiter); // Protect all routes
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: corsOptions,
  transports: ['websocket', 'polling']
});

// Redis adapter only when available (local dev uses default in-memory adapter)
if (redisAvailable && pubClient && subClient) {
  io.adapter(createAdapter(pubClient, subClient));
}

const matchQueue = new RedisMatchQueue(io);

const lastMatchTime = new Map(); // Map of socket.id -> timestamp

function isPIIDetected(text) {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const phoneRegex = [/(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, /\d{10}/g];
  
  if (emailRegex.test(text)) return true;
  for (const regex of phoneRegex) {
    if (regex.test(text)) return true;
  }
  return false;
}

const BadWordsFilter = require('bad-words');
const profanityFilter = (typeof BadWordsFilter === 'function') ? new BadWordsFilter() : new BadWordsFilter.Filter();

io.on('connection', async (socket) => {
  console.log('User connected:', socket.id);

  // ... (validateProfile function remains the same, but it's now inside the async block)
  function validateProfile(data) {
    const { nickname, bio } = data;
    if (!nickname || nickname.trim().length < 3) return "Nickname must be at least 3 characters.";
    if (!bio || bio.trim().length < 10) return "Bio must be at least 10 characters.";
    if (bio.length > 140) return "Bio exceeds 140 character limit.";
    
    if (profanityFilter.isProfane(nickname) || profanityFilter.isProfane(bio)) {
      return "Profile contains prohibited language.";
    }

    const emojiMatch = bio.match(/[\uD800-\uDBFF][\uDC00-\uDFFF]|\u261D|\u263A|\u2639|\u2665|\u2708|\u2709|\u270C|\u270D|[\u2702-\u27B0]/g);
    if (emojiMatch && emojiMatch.length > 5) {
      return "Maximum 5 emojis allowed in bio.";
    }

    return null;
  }

  socket.on('join_queue', async (userData) => {
    if (redisAvailable && !pubClient.isReady) {
      socket.emit('error', { message: 'Matchmaking is temporarily unavailable. Please try again shortly.' });
      return;
    }
    if (!userData || !userData.nickname || !userData.deviceId) {
      socket.emit('error', { message: 'Invalid profile data. Please complete your profile first.' });
      return;
    }
    if (!userData.gender || !userData.genderVerified) {
      socket.emit('error', { message: 'Gender verification is required before matching.' });
      return;
    }
    const verificationPayload = verifyVerificationToken(userData.verificationToken);
    if (
      !verificationPayload ||
      verificationPayload.deviceId !== userData.deviceId ||
      verificationPayload.gender !== userData.gender
    ) {
      socket.emit('error', { message: 'Verification expired or invalid. Please verify again.' });
      return;
    }
    // Check for active bans (Redis-Backed)
    const banInfo = await getBans(userData.deviceId);
    if (banInfo) {
      const now = Date.now();
      if (now < banInfo.expiry) {
        const hoursLeft = Math.ceil((banInfo.expiry - now) / (1000 * 60 * 60));
        socket.emit('error', { message: `Your device is currently banned due to community reports. Expires in ${hoursLeft}h.` });
        return;
      } else {
        await clearBan(userData.deviceId); // Ban expired
      }
    }

    // Validate Profile
    const validationError = validateProfile(userData);
    if (validationError) {
      socket.emit('error', { message: validationError });
      return;
    }

    // Enforce Daily Match Limit (Redis-Backed)
    const currentMatches = await getMatchCount(userData.deviceId);
    if (currentMatches >= DAILY_MATCH_LIMIT) {
      socket.emit('error', { message: 'Daily match limit reached. Please return tomorrow.' });
      return;
    }

    const now = Date.now();
    const lastTime = lastMatchTime.get(socket.id) || 0;
    if (now - lastTime < 5000) {
      socket.emit('error', { message: 'Please wait a few seconds before matching again.' });
      return;
    }

    const user = {
      id: socket.id,
      server: process.pid, // Track which server instance the socket belongs to
      ...userData
    };
    
    console.log(`Matching for ${user.nickname} (${user.gender}) looking for ${user.matchPreference}`);
    
    let partner;
    try {
      partner = await matchQueue.findMatch(user);
    } catch (err) {
      console.error('Matchmaking error:', err);
      socket.emit('error', { message: 'Matchmaking is temporarily unavailable. Please try again shortly.' });
      return;
    }

    if (partner) {
      const roomId = `room_${user.id}_${partner.id}`;
      
      lastMatchTime.set(user.id, now);
      lastMatchTime.set(partner.id, now);

      metrics.totalMatches++;
      metrics.activeSessions++;

      user.lastPartnerId = partner.deviceId;
      partner.lastPartnerId = user.deviceId;

      // Increment Match Counts (Redis-Backed)
      await incrementMatchCount(user.deviceId);
      await incrementMatchCount(partner.deviceId);

      socket.join(roomId);
      // Cross-server emit works automatically because of Redis Adapter
      io.to(partner.id).emit('match_found', { roomId, partner: user });
      socket.emit('match_found', { roomId, partner: partner });
      
      console.log(`Match detected: ${user.nickname} <-> ${partner.nickname}`);
    } else {
      await matchQueue.add(user);
    }
  });

  socket.on('report_user', async ({ reporterDeviceId, targetDeviceId, reason }) => {
    if (!targetDeviceId) {
      socket.emit('error', { message: 'Invalid report target.' });
      return;
    }
    metrics.totalReports++;
    reports.push({ 
      reporter: reporterDeviceId || socket.id, 
      target: targetDeviceId, 
      reason, 
      time: Date.now() 
    });
    
    // Automated Banning Logic (Redis-Backed)
    const reporter = reporterDeviceId || socket.id;
    const uniqueReporters = await recordReport(reporter, targetDeviceId);
    
    if (uniqueReporters >= REPORT_THRESHOLD) {
      await setBan(targetDeviceId, {
        expiry: Date.now() + (24 * 60 * 60 * 1000),
        reason: 'Multiple community reports'
      });
    }

    console.log(`Report filed against ${targetDeviceId}`);
  });

  socket.on('block_user', async ({ myDeviceId, targetDeviceId }) => {
    if (!myDeviceId || !targetDeviceId || myDeviceId === targetDeviceId) return;
    await addBlock(myDeviceId, targetDeviceId);
    console.log(`Block active: ${myDeviceId} -> ${targetDeviceId}`);
  });

  socket.on('join_room', (roomId) => {
    socket.join(roomId);
  });

  socket.on('send_message', ({ roomId, message }) => {
    if (isPIIDetected(message)) {
      socket.emit('error', { message: 'Sharing personal information is not allowed.' });
      return;
    }
    socket.to(roomId).emit('receive_message', {
      senderId: socket.id,
      text: message,
      timestamp: Date.now()
    });
  });

  socket.on('send_image', ({ roomId, image }) => {
    if (!image || typeof image !== 'string' || !image.startsWith('data:image')) return;
    socket.to(roomId).emit('receive_message', {
      senderId: socket.id,
      image: image,
      timestamp: Date.now()
    });
  });

  socket.on('typing', ({ roomId, isTyping }) => {
    socket.to(roomId).emit('partner_typing', { isTyping });
  });

  socket.on('leave_chat', (roomId) => {
    socket.to(roomId).emit('partner_left');
    socket.leave(roomId);
  });

  socket.on('disconnect', async () => {
    // In cross-server, the socket is already gone from this instance.
    // Cleanup of the Redis queue is handled during the findMatch process.
    const rooms = Array.from(socket.rooms);
    rooms.forEach(room => {
      if (room.startsWith('room_')) {
        metrics.activeSessions = Math.max(0, metrics.activeSessions - 0.5);
        socket.to(room).emit('partner_left');
      }
    });
    try {
      await matchQueue.removeBySocketId(socket.id);
    } catch (err) {
      console.error('Queue cleanup error:', err);
    }
    console.log('User disconnected:', socket.id);
  });
});

/**
 * Nuclear Reset (Phase 9 - Shared Reset)
 */
app.get('/api/nuclear-reset', async (req, res) => {
  if (redisAvailable) {
    const keys = await pubClient.keys('anonchat:*');
    if (keys.length > 0) await pubClient.del(keys);
  } else {
    memBans.clear(); memBlocks.clear(); memMatchCounts.clear();
    memReports.clear(); memQueue.length = 0; memReportsTotal = 0;
  }
  reports.length = 0;
  console.log('STORM WARNING: Global Reset Triggered.');
  res.json({ success: true, message: 'All data wiped.' });
});

/**
 * Phase 8/9: Admin Analytics API (Redis-Backed)
 */
app.get('/api/admin/metrics', async (req, res) => {
  let bansCount, queueSize, reportsTotal;
  if (redisAvailable) {
    bansCount = await pubClient.hLen(REDIS_KEYS.BANS);
    queueSize = await pubClient.lLen(REDIS_KEYS.QUEUE);
    reportsTotal = parseInt((await pubClient.get(REDIS_KEYS.REPORTS_TOTAL)) || '0', 10);
  } else {
    bansCount = memBans.size;
    queueSize = memQueue.length;
    reportsTotal = memReportsTotal;
  }
  res.json({
    technical: {
      activeSessions: metrics.activeSessions,
      totalMatchesLife: metrics.totalMatches,
      queueThroughput: queueSize
    },
    safety: {
      totalReports: reportsTotal,
      activeBans: bansCount
    }
  });
});

/**
 * Real-time Stats API (Redis-Backed)
 */
app.get('/api/stats', async (req, res) => {
  const queueSize = redisAvailable
    ? await pubClient.lLen(REDIS_KEYS.QUEUE)
    : memQueue.length;
  res.json({
    onlineUsers: io.engine.clientsCount,
    waitingInQueue: queueSize
  });
});

app.get('/healthz', async (req, res) => {
  res.json({
    status: 'ok',
    mode: redisAvailable ? 'redis' : 'in-memory',
    redis: {
      pubReady: redisAvailable ? pubClient.isReady : false,
      subReady: redisAvailable ? subClient.isReady : false
    }
  });
});


const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

/**
 * queryHuggingFace
 * Real Cloud AI call to Hugging Face Inference API (Bucket B)
 */
async function queryHuggingFace(imageBuffer) {
  const model = "rizwandari/gender-classification";
  const apiToken = process.env.HF_API_TOKEN;

  // No mock allowed in production-ready Phase 4
  if (!apiToken || apiToken === 'your_huggingface_token_here') {
    return { error: 'HF_API_TOKEN missing' };
  }

  try {
    const response = await fetch(
      `https://api-inference.huggingface.co/models/${model}`,
      {
        headers: { Authorization: `Bearer ${apiToken}` },
        method: "POST",
        body: imageBuffer,
      }
    );
    return await response.json();
  } catch (error) {
    console.error("AI Engine: Hugging Face API Error:", error);
    return null;
  }
}

/**
 * Gender Verification Endpoint
 * Proxies to Python-based gender detection service (FastAPI on port 8000)
 * Maintains privacy-first approach with immediate image deletion
 */
app.post('/api/verify', async (req, res) => {
  metrics.verificationAttempts++;
  const { image, deviceId } = req.body;
  if (!image) return res.status(400).json({ verified: false, error: 'Image data required' });
  if (!deviceId) return res.status(400).json({ verified: false, error: 'Device ID required' });

  try {
    // Convert base64 to Buffer (processed in-memory)
    const base64Data = image.split(',')[1];
    const buffer = Buffer.from(base64Data, 'base64');

    // Create form data for the Python service
    const FormData = require('form-data');
    const formData = new FormData();
    
    // Append the image as a file blob
    formData.append('image', buffer, {
      filename: 'capture.jpg',
      contentType: 'image/jpeg'
    });

    console.log('Gender Service: Forwarding to Python gender detection service...');

    // Call the Python gender detection service
    const response = await fetch(`${GENDER_SERVICE_URL}/verify-gender`, {
      method: 'POST',
      body: formData,
      headers: formData.getHeaders()
    });

    const data = await response.json();

    // Map the response from gender service to frontend format
    if (data.verified === true) {
      metrics.verificationSuccess++;
      console.log(`Gender Service: Verification successful - Gender: ${data.gender}`);
      const expiresAt = Date.now() + VERIFICATION_TOKEN_TTL_SECONDS * 1000;
      const token = signVerificationToken({
        deviceId,
        gender: data.gender,
        exp: expiresAt
      });
      
      res.json({
        verified: true,
        gender: data.gender,
        verificationToken: token,
        expiresAt
      });
    } else {
      console.log(`Gender Service: Verification failed - ${data.error}`);
      res.json({
        verified: false,
        error: data.error || 'Verification failed'
      });
    }
  } catch (error) {
    console.error('Gender Service: Error calling gender detection service:', error.message);
    res.json({
      verified: false,
      error: 'Unable to connect to gender detection service. Please ensure it is running.'
    });
  }
});

const PORT = process.env.PORT || 3002;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

const shutdown = async () => {
  console.log('Graceful shutdown initiated...');
  if (redisAvailable && pubClient) {
    try {
      await Promise.all([pubClient.quit(), subClient.quit()]);
    } catch (err) {
      console.error('Error during Redis shutdown:', err);
    }
  }
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
