// server.js - Railway Backend с Multi-Key Failover (6 попыток)
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// API KEYS POOL с Failover & Load Balancing
// ============================================

class APIKeyPool {
    constructor() {
        this.keys = [];
        this.keyStatus = new Map();
        this.currentIndex = 0;
        this._loadKeys();
        this._startHealthMonitor();
    }

    _loadKeys() {
        for (let i = 1; i <= 10; i++) {
            const key = process.env[`OPENAI_API_KEY_${i}`];
            if (key && key.startsWith('sk-')) {
                this.keys.push(key);
                this.keyStatus.set(key, {
                    healthy: true,
                    lastCheck: Date.now(),
                    failCount: 0,
                    successCount: 0,
                    lastError: null
                });
            }
        }

        if (this.keys.length === 0) {
            const fallbackKey = process.env.OPENAI_API_KEY;
            if (fallbackKey && fallbackKey.startsWith('sk-')) {
                this.keys.push(fallbackKey);
                this.keyStatus.set(fallbackKey, {
                    healthy: true,
                    lastCheck: Date.now(),
                    failCount: 0,
                    successCount: 0,
                    lastError: null
                });
            }
        }

        console.log(`🔑 Loaded ${this.keys.length} API keys`);
        this.keys.forEach((key, idx) => {
            console.log(`   Key ${idx + 1}: ${key.substring(0, 10)}...${key.substring(key.length - 4)}`);
        });
    }

    _startHealthMonitor() {
        setInterval(() => {
            this._checkUnhealthyKeys();
        }, 5 * 60 * 1000);
    }

    async _checkUnhealthyKeys() {
        console.log('🏥 Health check: checking unhealthy keys...');
        
        for (const [key, status] of this.keyStatus.entries()) {
            if (!status.healthy) {
                const minutesSinceCheck = (Date.now() - status.lastCheck) / 1000 / 60;
                
                if (minutesSinceCheck > 10) {
                    console.log(`🔄 Attempting to recover key: ${key.substring(0, 10)}...`);
                    
                    try {
                        const response = await fetch('https://api.openai.com/v1/models', {
                            headers: { 'Authorization': `Bearer ${key}` }
                        });
                        
                        if (response.ok) {
                            status.healthy = true;
                            status.failCount = 0;
                            status.lastCheck = Date.now();
                            console.log(`✅ Key recovered: ${key.substring(0, 10)}...`);
                        }
                    } catch (error) {
                        console.log(`❌ Key still dead: ${key.substring(0, 10)}...`);
                    }
                }
            }
        }
    }

    getHealthyKeys() {
        return this.keys.filter(key => this.keyStatus.get(key).healthy);
    }

    getNextKey() {
        const healthyKeys = this.getHealthyKeys();
        
        if (healthyKeys.length === 0) {
            throw new Error('No healthy API keys available');
        }

        const key = healthyKeys[this.currentIndex % healthyKeys.length];
        this.currentIndex++;
        
        return key;
    }

    markKeyFailed(key, error) {
        const status = this.keyStatus.get(key);
        if (!status) return;

        status.failCount++;
        status.lastError = error.message;
        status.lastCheck = Date.now();

        if (status.failCount >= 3) {
            status.healthy = false;
            console.warn(`⚠️ Key marked as unhealthy after ${status.failCount} failures: ${key.substring(0, 10)}...`);
            console.warn(`   Last error: ${error.message}`);
        }
    }

    markKeySuccess(key) {
        const status = this.keyStatus.get(key);
        if (!status) return;

        status.successCount++;
        status.failCount = Math.max(0, status.failCount - 1);
        status.lastCheck = Date.now();
        
        if (!status.healthy) {
            status.healthy = true;
            console.log(`✅ Key auto-recovered: ${key.substring(0, 10)}...`);
        }
    }

    // 🆕 НОВЫЙ МЕТОД: Поиск ключа по label
    findKeyByLabel(keyLabel) {
        for (const key of this.keys) {
            const label = `${key.substring(0, 10)}...${key.substring(key.length - 4)}`;
            if (label === keyLabel) {
                return key;
            }
        }
        return null;
    }

    // 🆕 НОВЫЙ МЕТОД: Blacklist ключа по label
    blacklistKey(keyLabel, reason) {
        const key = this.findKeyByLabel(keyLabel);
        if (!key) {
            console.warn(`⚠️ Key not found for blacklist: ${keyLabel}`);
            return false;
        }

        const status = this.keyStatus.get(key);
        if (!status) return false;

        status.healthy = false;
        status.failCount = 999;
        status.lastError = reason;
        status.lastCheck = Date.now();

        console.warn(`🚫 Key blacklisted: ${keyLabel}`);
        console.warn(`   Reason: ${reason}`);
        
        return true;
    }

    getStats() {
        const stats = {
            total: this.keys.length,
            healthy: 0,
            unhealthy: 0,
            keys: []
        };

        for (const [key, status] of this.keyStatus.entries()) {
            if (status.healthy) stats.healthy++;
            else stats.unhealthy++;

            stats.keys.push({
                key: `${key.substring(0, 10)}...${key.substring(key.length - 4)}`,
                healthy: status.healthy,
                successCount: status.successCount,
                failCount: status.failCount,
                lastError: status.lastError,
                lastCheck: new Date(status.lastCheck).toISOString()
            });
        }

        return stats;
    }
}

const keyPool = new APIKeyPool();
const rateLimitStore = new Map();

const allowedOrigins = [
  'http://localhost:8000',
  'http://localhost:3000',
  'https://yourdomain.com',
  'https://cdpn.io',
  'https://codepen.io',
  'https://hypnologue.art',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn('❌ Blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());

app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path} from ${req.ip}`);
  next();
});

function checkRateLimit(ip, projectId) {
  const key = `${ip}:${projectId}`;
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const maxRequests = 10;
  
  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, { count: 0, resetAt: now + windowMs });
  }
  
  const data = rateLimitStore.get(key);
  
  if (now > data.resetAt) {
    data.count = 0;
    data.resetAt = now + windowMs;
  }
  
  data.count++;
  
  if (data.count > maxRequests) {
    const resetIn = Math.ceil((data.resetAt - now) / 1000 / 60);
    return {
      allowed: false,
      message: `Rate limit exceeded. Try again in ${resetIn} minutes.`,
      resetIn
    };
  }
  
  return {
    allowed: true,
    remaining: maxRequests - data.count,
    resetAt: data.resetAt
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now > data.resetAt + 60000) {
      rateLimitStore.delete(key);
    }
  }
  console.log('🧹 Cleanup: rate limit store size:', rateLimitStore.size);
}, 5 * 60 * 1000);

app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'OpenAI Auth Gateway',
    version: '2.3.0',
    features: ['ephemeral-keys', 'standard-api-keys', 'multi-key-failover', 'client-blacklist'],
    maxAttempts: 6,
    timestamp: new Date().toISOString()
  });
});

// 1️⃣ EPHEMERAL KEY для Realtime API (6 ПОПЫТОК!)
app.post('/session', async (req, res) => {
    try {
        const { project, voice = 'shimmer', maxDuration = 300000 } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;
        
        if (!project) {
            return res.status(400).json({ 
                error: 'Project ID required',
                code: 'MISSING_PROJECT'
            });
        }
        
        const rateCheck = checkRateLimit(clientIp, project);
        if (!rateCheck.allowed) {
            return res.status(429).json({
                error: rateCheck.message,
                code: 'RATE_LIMIT_EXCEEDED',
                resetIn: rateCheck.resetIn
            });
        }
        
        const healthyKeys = keyPool.getHealthyKeys();
        if (healthyKeys.length === 0) {
            console.error('❌ No healthy API keys available!');
            return res.status(503).json({ 
                error: 'Service temporarily unavailable - no healthy API keys',
                code: 'NO_HEALTHY_KEYS'
            });
        }
        
        console.log(`🔑 Generating EPHEMERAL key for: ${project}, voice: ${voice}`);
        console.log(`📊 Healthy keys: ${healthyKeys.length}/${keyPool.keys.length}`);
        
        let lastError = null;
        const maxAttempts = Math.min(6, healthyKeys.length);
        
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            const apiKey = keyPool.getNextKey();
            const keyLabel = `${apiKey.substring(0, 10)}...${apiKey.substring(apiKey.length - 4)}`;
            
            try {
                console.log(`🔄 Attempt ${attempt + 1}/${maxAttempts} with key: ${keyLabel}`);
                
                const openaiResponse = await fetch('https://api.openai.com/v1/realtime/sessions', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        model: 'gpt-4o-realtime-preview-2024-12-17',
                        voice: voice
                    })
                });
                
                if (!openaiResponse.ok) {
                    const errorText = await openaiResponse.text();
                    throw new Error(`OpenAI API error: ${openaiResponse.status} - ${errorText}`);
                }
                
                const data = await openaiResponse.json();
                
                keyPool.markKeySuccess(apiKey);
                
                console.log(`✅ Ephemeral key generated with: ${keyLabel} on attempt ${attempt + 1}`);
                
                return res.json({
                    ephemeralKey: data.client_secret.value,
                    expiresAt: data.client_secret.expires_at,
                    maxDuration: maxDuration,
                    project: project,
                    voice: voice,
                    rateLimit: {
                        remaining: rateCheck.remaining,
                        resetAt: rateCheck.resetAt
                    },
                    _meta: {
                        keyUsed: keyLabel,
                        attempt: attempt + 1,
                        maxAttempts: maxAttempts,
                        healthyKeys: keyPool.getHealthyKeys().length
                    }
                });
                
            } catch (error) {
                lastError = error;
                console.error(`❌ Attempt ${attempt + 1} failed with key ${keyLabel}:`, error.message);
                keyPool.markKeyFailed(apiKey, error);
                
                if (attempt < maxAttempts - 1) {
                    console.log(`🔄 Trying next key...`);
                    continue;
                }
            }
        }
        
        console.error(`❌ All ${maxAttempts} failover attempts exhausted`);
        return res.status(503).json({
            error: `Failed to generate session key after ${maxAttempts} attempts`,
            code: 'ALL_KEYS_FAILED',
            details: lastError?.message,
            healthyKeys: keyPool.getHealthyKeys().length,
            totalKeys: keyPool.keys.length,
            attempts: maxAttempts
        });
        
    } catch (error) {
        console.error('❌ Server error:', error);
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
            message: error.message
        });
    }
});

// 2️⃣ STANDARD API KEY
app.post('/api-key', async (req, res) => {
    try {
        const { project } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;
        
        if (!project) {
            return res.status(400).json({ 
                error: 'Project ID required',
                code: 'MISSING_PROJECT'
            });
        }
        
        const rateCheck = checkRateLimit(clientIp, project);
        if (!rateCheck.allowed) {
            return res.status(429).json({
                error: rateCheck.message,
                code: 'RATE_LIMIT_EXCEEDED',
                resetIn: rateCheck.resetIn
            });
        }
        
        const healthyKeys = keyPool.getHealthyKeys();
        if (healthyKeys.length === 0) {
            return res.status(503).json({ 
                error: 'No healthy API keys',
                code: 'NO_HEALTHY_KEYS'
            });
        }
        
        const apiKey = keyPool.getNextKey();
        const keyLabel = `${apiKey.substring(0, 10)}...${apiKey.substring(apiKey.length - 4)}`;
        
        console.log(`🔑 Standard API key provided: ${keyLabel} for ${project}`);
        
        res.json({
            apiKey: apiKey,
            keyLabel: keyLabel,
            project: project,
            rateLimit: {
                remaining: rateCheck.remaining,
                resetAt: rateCheck.resetAt
            }
        });
        
    } catch (error) {
        console.error('❌ Error providing API key:', error);
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
            message: error.message
        });
    }
});

// 🆕 3️⃣ BLACKLIST KEY (Client-reported failures)
app.post('/session/blacklist', (req, res) => {
    try {
        const { keyLabel, reason } = req.body;
        
        if (!keyLabel) {
            return res.status(400).json({
                error: 'keyLabel is required',
                code: 'MISSING_KEY_LABEL'
            });
        }
        
        if (!reason) {
            return res.status(400).json({
                error: 'reason is required',
                code: 'MISSING_REASON'
            });
        }
        
        const success = keyPool.blacklistKey(keyLabel, reason);
        
        if (!success) {
            return res.status(404).json({
                error: 'Key not found',
                code: 'KEY_NOT_FOUND',
                keyLabel: keyLabel
            });
        }
        
        res.json({
            success: true,
            message: 'Key blacklisted successfully',
            keyLabel: keyLabel,
            reason: reason,
            healthyKeys: keyPool.getHealthyKeys().length
        });
        
    } catch (error) {
        console.error('❌ Error blacklisting key:', error);
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
            message: error.message
        });
    }
});

app.get('/analytics', (req, res) => {
    const stats = {
        activeConnections: rateLimitStore.size,
        timestamp: new Date().toISOString(),
        rateLimits: Array.from(rateLimitStore.entries()).map(([key, data]) => ({
            key,
            count: data.count,
            resetAt: new Date(data.resetAt).toISOString()
        }))
    };
    
    res.json(stats);
});

app.get('/keys/health', (req, res) => {
    const stats = keyPool.getStats();
    
    res.json({
        timestamp: new Date().toISOString(),
        summary: {
            total: stats.total,
            healthy: stats.healthy,
            unhealthy: stats.unhealthy,
            healthPercentage: ((stats.healthy / stats.total) * 100).toFixed(1) + '%'
        },
        keys: stats.keys
    });
});

app.post('/keys/check', async (req, res) => {
    const { adminKey } = req.body;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    console.log('🏥 Manual health check initiated...');
    
    const results = [];
    
    for (const key of keyPool.keys) {
        const keyLabel = `${key.substring(0, 10)}...${key.substring(key.length - 4)}`;
        
        try {
            const response = await fetch('https://api.openai.com/v1/models', {
                headers: { 'Authorization': `Bearer ${key}` }
            });
            
            const isHealthy = response.ok;
            const status = keyPool.keyStatus.get(key);
            status.healthy = isHealthy;
            status.lastCheck = Date.now();
            
            results.push({
                key: keyLabel,
                status: isHealthy ? 'healthy' : 'unhealthy',
                httpStatus: response.status
            });
            
            console.log(`${isHealthy ? '✅' : '❌'} ${keyLabel}: ${response.status}`);
            
        } catch (error) {
            results.push({
                key: keyLabel,
                status: 'error',
                error: error.message
            });
            console.log(`❌ ${keyLabel}: ${error.message}`);
        }
    }
    
    res.json({
        message: 'Health check completed',
        results: results,
        summary: keyPool.getStats()
    });
});

app.post('/keys/recover', async (req, res) => {
    const { adminKey, keyIndex } = req.body;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    if (keyIndex < 0 || keyIndex >= keyPool.keys.length) {
        return res.status(400).json({ error: 'Invalid key index' });
    }
    
    const key = keyPool.keys[keyIndex];
    const status = keyPool.keyStatus.get(key);
    
    status.failCount = 0;
    status.healthy = true;
    status.lastCheck = Date.now();
    
    console.log(`🔄 Key ${keyIndex} manually recovered`);
    
    res.json({
        message: 'Key recovered',
        keyIndex: keyIndex,
        status: status
    });
});

app.post('/admin/reset-limits', (req, res) => {
  const { adminKey } = req.body;
  
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  rateLimitStore.clear();
  console.log('🔄 Rate limits cleared by admin');
  
  res.json({ 
    success: true, 
    message: 'All rate limits cleared' 
  });
});

app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /',
      'POST /session',
      'POST /api-key',
      'POST /session/blacklist',
      'GET /analytics',
      'GET /keys/health',
      'POST /keys/check',
      'POST /keys/recover',
      'POST /admin/reset-limits'
    ]
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

app.listen(PORT, () => {
    console.log('🚀 OpenAI Auth Gateway v2.3 (6 Attempts + Client Blacklist)');
    console.log(`📡 Server running on port ${PORT}`);
    console.log(`🔑 API Keys: ${keyPool.keys.length} loaded`);
    console.log(`   Healthy: ${keyPool.getHealthyKeys().length}`);
    console.log(`   Strategy: Round-robin with automatic failover (6 attempts)`);
    console.log(`🛡️ CORS enabled for: ${allowedOrigins.join(', ')}`);
    console.log(`⏰ Time: ${new Date().toISOString()}`);
    console.log(`\n📊 Endpoints:`);
    console.log(`   POST /session              - Generate ephemeral key (6 attempts)`);
    console.log(`   POST /api-key              - Get standard API key`);
    console.log(`   POST /session/blacklist    - Blacklist bad key (client-reported)`);
    console.log(`   GET  /analytics            - Rate limit stats`);
    console.log(`   GET  /keys/health          - API keys health status`);
    console.log(`   POST /keys/check           - Manual health check (admin)`);
    console.log(`   POST /keys/recover         - Recover specific key (admin)`);
    console.log(`   POST /admin/reset-limits   - Reset rate limits (admin)`);
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully');
  process.exit(0);
});
