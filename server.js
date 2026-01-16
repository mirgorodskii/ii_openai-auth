// server.js - Railway Backend с Multi-Key Failover
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
  'https://cdpn.io',
  'https://codepen.io',
  'https://hypnologue.art',
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

// Главный endpoint - генерация ephemeral key с Failover
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
        
        // Проверка наличия ключей
        const healthyKeys = keyPool.getHealthyKeys();
        if (healthyKeys.length === 0) {
            console.error('❌ No healthy API keys available!');
            return res.status(503).json({ 
                error: 'Service temporarily unavailable - no healthy API keys',
                code: 'NO_HEALTHY_KEYS'
            });
        }
        
        console.log(`🔑 Attempting key generation for project: ${project}, voice: ${voice}`);
        console.log(`📊 Healthy keys: ${healthyKeys.length}/${keyPool.keys.length}`);
        
        // Пробуем ключи по очереди с failover
        let lastError = null;
        const maxAttempts = Math.min(3, healthyKeys.length); // Максимум 3 попытки
        
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
                
                // ✅ Успех! Помечаем ключ как рабочий
                keyPool.markKeySuccess(apiKey);
                
                console.log(`✅ Key generated successfully with key: ${keyLabel}`);
                console.log(`📊 Stats: ${keyPool.getStats().healthy} healthy keys`);
                
                // Возвращаем данные клиенту
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
                    // Дополнительная информация для мониторинга
                    _meta: {
                        keyUsed: keyLabel,
                        attempt: attempt + 1,
                        healthyKeys: keyPool.getHealthyKeys().length
                    }
                });
                
            } catch (error) {
                lastError = error;
                console.error(`❌ Attempt ${attempt + 1} failed with key ${keyLabel}:`, error.message);
                
                // Помечаем ключ как проблемный
                keyPool.markKeyFailed(apiKey, error);
                
                // Если есть еще попытки - продолжаем
                if (attempt < maxAttempts - 1) {
                    console.log(`🔄 Trying next key...`);
                    continue;
                }
            }
        }
        
        // Если все попытки провалились
        console.error('❌ All failover attempts exhausted');
        return res.status(503).json({
            error: 'Failed to generate session key after multiple attempts',
            code: 'ALL_KEYS_FAILED',
            details: lastError?.message,
            healthyKeys: keyPool.getHealthyKeys().length,
            totalKeys: keyPool.keys.length
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

// 🔥 НОВЫЙ: Мониторинг состояния API ключей
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

// 🔥 НОВЫЙ: Принудительная проверка всех ключей
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

// 🔥 НОВЫЙ: Восстановление конкретного ключа
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
    
    // Сбрасываем счетчики
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
      'GET /keys/health',
      'POST /keys/check',
      'POST /keys/recover',
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
    console.log('🚀 OpenAI Auth Gateway with Multi-Key Failover');
    console.log(`📡 Server running on port ${PORT}`);
    console.log(`🔑 API Keys: ${keyPool.keys.length} loaded`);
    console.log(`   Healthy: ${keyPool.getHealthyKeys().length}`);
    console.log(`   Strategy: Round-robin with automatic failover`);
    console.log(`🛡️ CORS enabled for: ${allowedOrigins.join(', ')}`);
    console.log(`⏰ Time: ${new Date().toISOString()}`);
    console.log(`\n📊 Endpoints:`);
    console.log(`   POST /session          - Generate ephemeral key`);
    console.log(`   GET  /analytics        - Rate limit stats`);
    console.log(`   GET  /keys/health      - API keys health status`);
    console.log(`   POST /keys/check       - Manual health check (admin)`);
    console.log(`   POST /keys/recover     - Recover specific key (admin)`);
    console.log(`   POST /admin/reset-limits - Reset rate limits (admin)`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

