// server.js - Railway Backend с Multi-Key Failover
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// API KEYS POOL с Failover & Load Balancing
// ============================================

class APIKeyPool {
    constructor() {
        this.keys = [];
        this.keyStatus = new Map(); // key -> { healthy, lastCheck, failCount, successCount }
        this.currentIndex = 0;
        this._loadKeys();
        this._startHealthMonitor();
    }

    _loadKeys() {
        // Загружаем ключи из environment variables
        // OPENAI_API_KEY_1, OPENAI_API_KEY_2, etc.
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

        // Fallback: если нет пронумерованных ключей, используем OPENAI_API_KEY
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
        // Каждые 5 минут проверяем "мертвые" ключи
        setInterval(() => {
            this._checkUnhealthyKeys();
        }, 5 * 60 * 1000);
    }

    async _checkUnhealthyKeys() {
        console.log('🏥 Health check: checking unhealthy keys...');
        
        for (const [key, status] of this.keyStatus.entries()) {
            if (!status.healthy) {
                // Если ключ был мертв больше 10 минут, пробуем его восстановить
                const minutesSinceCheck = (Date.now() - status.lastCheck) / 1000 / 60;
                
                if (minutesSinceCheck > 10) {
                    console.log(`🔄 Attempting to recover key: ${key.substring(0, 10)}...`);
                    
                    // Пробуем простой запрос
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

        // Round-robin: берем следующий здоровый ключ
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

        // Если ключ упал 3 раза подряд - помечаем как нездоровый
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
        status.failCount = Math.max(0, status.failCount - 1); // Уменьшаем счетчик ошибок
        status.lastCheck = Date.now();
        
        // Если ключ был нездоровым, но сейчас сработал - восстанавливаем
        if (!status.healthy) {
            status.healthy = true;
            console.log(`✅ Key auto-recovered: ${key.substring(0, 10)}...`);
        }
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

// Инициализируем пул ключей
const keyPool = new APIKeyPool();

// Rate limiting storage
const rateLimitStore = new Map();

// CORS - разрешаем только твои домены
const allowedOrigins = [
  'http://localhost:8000',
  'http://localhost:3000',
  'https://yourdomain.com',
  // Добавь свои домены
];

app.use(cors({
  origin: (origin, callback) => {
    // Разрешаем requests без origin (например Postman)
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

// Middleware для логирования
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path} from ${req.ip}`);
  next();
});

// Rate Limiter - базовая защита
function checkRateLimit(ip, projectId) {
  const key = `${ip}:${projectId}`;
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 час
  const maxRequests = 10; // 10 ключей в час
  
  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, { count: 0, resetAt: now + windowMs });
  }
  
  const data = rateLimitStore.get(key);
  
  // Сброс если окно истекло
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

// Очистка старых записей каждые 5 минут
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now > data.resetAt + 60000) { // +1 минута после истечения
      rateLimitStore.delete(key);
    }
  }
  console.log('🧹 Cleanup: rate limit store size:', rateLimitStore.size);
}, 5 * 60 * 1000);

// Health check
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'OpenAI Auth Gateway',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Главный endpoint - генерация ephemeral key
app.post('/session', async (req, res) => {
  try {
    const { project, voice = 'shimmer', maxDuration = 300000 } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    
    // Валидация
    if (!project) {
      return res.status(400).json({ 
        error: 'Project ID required',
        code: 'MISSING_PROJECT'
      });
    }
    
    // Rate limiting
    const rateCheck = checkRateLimit(clientIp, project);
    if (!rateCheck.allowed) {
      return res.status(429).json({
        error: rateCheck.message,
        code: 'RATE_LIMIT_EXCEEDED',
        resetIn: rateCheck.resetIn
      });
    }
    
    // Проверка API ключа
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      console.error('❌ OPENAI_API_KEY not configured');
      return res.status(500).json({ 
        error: 'Server configuration error',
        code: 'MISSING_API_KEY'
      });
    }
    
    // Запрос ephemeral key от OpenAI
    console.log(`🔑 Generating key for project: ${project}, voice: ${voice}`);
    
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
      console.error('❌ OpenAI API error:', openaiResponse.status, errorText);
      
      return res.status(openaiResponse.status).json({
        error: 'Failed to generate session key',
        code: 'OPENAI_API_ERROR',
        details: errorText
      });
    }
    
    const data = await openaiResponse.json();
    
    // Логирование для аналитики
    console.log(`✅ Key generated for ${project} | Remaining: ${rateCheck.remaining}`);
    
    // Возвращаем данные клиенту
    res.json({
      ephemeralKey: data.client_secret.value,
      expiresAt: data.client_secret.expires_at,
      maxDuration: maxDuration,
      project: project,
      voice: voice,
      rateLimit: {
        remaining: rateCheck.remaining,
        resetAt: rateCheck.resetAt
      }
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

// Analytics endpoint (простой пример)
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

// Admin endpoint - очистить rate limits (для emergency)
app.post('/admin/reset-limits', (req, res) => {
  const { adminKey } = req.body;
  
  // Простая защита (в продакшене используй proper auth)
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

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /',
      'POST /session',
      'GET /analytics',
      'POST /admin/reset-limits'
    ]
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

app.listen(PORT, () => {
  console.log('🚀 OpenAI Auth Gateway started');
  console.log(`📡 Server running on port ${PORT}`);
  console.log(`🔑 API key configured: ${process.env.OPENAI_API_KEY ? 'YES' : 'NO'}`);
  console.log(`🛡️ CORS enabled for: ${allowedOrigins.join(', ')}`);
  console.log(`⏰ Time: ${new Date().toISOString()}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully');
  process.exit(0);
});
