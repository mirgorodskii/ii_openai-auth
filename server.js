// server.js - Railway Backend with Multi-Key Failover
// Updated for OpenAI Realtime client_secrets flow
// Fix: voice is NOT session.voice. It goes into session.audio.output.voice.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// API KEYS POOL
// ============================================

class APIKeyPool {
  constructor() {
    this.keys = [];
    this.keyStatus = new Map();
    this.currentIndex = 0;

    this._loadKeys();
    this._startHealthMonitor();
  }

  _labelKey(key) {
    return `${key.substring(0, 10)}...${key.substring(key.length - 4)}`;
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
      console.log(`   Key ${idx + 1}: ${this._labelKey(key)}`);
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
          console.log(`🔄 Attempting to recover key: ${this._labelKey(key)}`);

          try {
            const response = await fetch('https://api.openai.com/v1/models', {
              headers: {
                Authorization: `Bearer ${key}`
              }
            });

            const text = await response.text();

            if (response.ok) {
              status.healthy = true;
              status.failCount = 0;
              status.lastCheck = Date.now();
              status.lastError = null;

              console.log(`✅ Key recovered: ${this._labelKey(key)}`);
            } else {
              status.lastError = `Health check failed: ${response.status} - ${text}`;
              status.lastCheck = Date.now();

              console.log(`❌ Key still unhealthy: ${this._labelKey(key)} | ${response.status}`);
            }
          } catch (error) {
            status.lastError = error.message;
            status.lastCheck = Date.now();

            console.log(`❌ Key still dead: ${this._labelKey(key)} | ${error.message}`);
          }
        }
      }
    }
  }

  getHealthyKeys() {
    return this.keys.filter((key) => {
      const status = this.keyStatus.get(key);
      return status && status.healthy;
    });
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

      console.warn(`⚠️ Key marked unhealthy after ${status.failCount} failures: ${this._labelKey(key)}`);
      console.warn(`   Last error: ${error.message}`);
    }
  }

  markKeySuccess(key) {
    const status = this.keyStatus.get(key);
    if (!status) return;

    status.successCount++;
    status.failCount = Math.max(0, status.failCount - 1);
    status.lastCheck = Date.now();
    status.lastError = null;

    if (!status.healthy) {
      status.healthy = true;
      console.log(`✅ Key auto-recovered: ${this._labelKey(key)}`);
    }
  }

  findKeyByLabel(keyLabel) {
    for (const key of this.keys) {
      if (this._labelKey(key) === keyLabel) {
        return key;
      }
    }

    return null;
  }

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
        key: this._labelKey(key),
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

// ============================================
// CORS
// ============================================

const allowedOrigins = [
  'http://localhost:8000',
  'http://localhost:3000',
  'https://yourdomain.com',
  'https://cdpn.io',
  'https://codepen.io',
  'https://hypnologue.art'
];

function isAllowedOrigin(origin) {
  if (!origin) return true;

  if (allowedOrigins.includes(origin)) return true;

  // CodePen dynamic domains
  if (/^https:\/\/.*\.codepen\.dev$/.test(origin)) return true;

  // Railway frontend previews, if you ever use them
  if (/^https:\/\/.*\.up\.railway\.app$/.test(origin)) return true;

  return false;
}

app.use(
  cors({
    origin: (origin, callback) => {
      if (isAllowedOrigin(origin)) {
        callback(null, true);
      } else {
        console.warn('❌ Blocked origin:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  })
);

app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.path} from ${req.ip}`);
  next();
});

// ============================================
// RATE LIMIT
// ============================================

function checkRateLimit(ip, projectId) {
  const key = `${ip}:${projectId}`;
  const now = Date.now();

  const windowMs = 60 * 60 * 1000;
  const maxRequests = Number(process.env.RATE_LIMIT_MAX || 100);

  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, {
      count: 0,
      resetAt: now + windowMs
    });
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

// ============================================
// HELPERS
// ============================================

function normalizeVoice(voice) {
  const allowedVoices = new Set([
    'alloy',
    'ash',
    'ballad',
    'coral',
    'echo',
    'marin',
    'sage',
    'shimmer',
    'verse',
    'cedar'
  ]);

  if (!voice || typeof voice !== 'string') return 'shimmer';

  const normalized = voice.trim().toLowerCase();

  if (allowedVoices.has(normalized)) {
    return normalized;
  }

  console.warn(`⚠️ Unknown voice "${voice}", falling back to shimmer`);
  return 'shimmer';
}

function normalizeRealtimeModel(model) {
  const allowedModels = new Set([
    'gpt-realtime',
    'gpt-realtime-mini',
    'gpt-realtime-1.5',
    'gpt-realtime-2',
    'gpt-realtime-2.1-mini',
    'gpt-realtime-2.1'
  ]);

  const fallbackModel = process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime-2.1';

  if (!model || typeof model !== 'string') return fallbackModel;

  const normalized = model.trim();

  if (allowedModels.has(normalized)) {
    return normalized;
  }

  console.warn(`⚠️ Unknown Realtime model "${model}", falling back to ${fallbackModel}`);
  return fallbackModel;
}

function shouldExposeDebug(req) {
  return (
    process.env.NODE_ENV !== 'production' ||
    req.query.debug === '1' ||
    req.headers['x-debug'] === '1'
  );
}

async function createRealtimeClientSecret(apiKey, options = {}) {
  const {
    voice = 'shimmer',
    model = process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime-2.1',
    instructions = null
  } = options;

  // Important:
  // Do NOT use session.voice.
  // The API rejected it with: Unknown parameter: 'session.voice'.
  const session = {
    type: 'realtime',
    model,

    audio: {
      output: {
        voice
      },

      input: {
        turn_detection: {
          type: 'server_vad'
        }
      }
    }
  };

  if (instructions && typeof instructions === 'string') {
    session.instructions = instructions;
  }

  const response = await fetch('https://api.openai.com/v1/realtime/client_secrets', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      session
    })
  });

  const rawText = await response.text();

  let data = null;

  try {
    data = rawText ? JSON.parse(rawText) : null;
  } catch (error) {
    throw new Error(`OpenAI returned non-JSON response: ${response.status} - ${rawText}`);
  }

  if (!response.ok) {
    throw new Error(`OpenAI API error: ${response.status} - ${JSON.stringify(data)}`);
  }

  const ephemeralKey =
    data?.value ||
    data?.client_secret?.value ||
    data?.client_secret ||
    data?.secret?.value ||
    data?.secret;

  const expiresAt =
    data?.expires_at ||
    data?.client_secret?.expires_at ||
    data?.secret?.expires_at ||
    null;

  if (!ephemeralKey) {
    throw new Error(`No ephemeral key in OpenAI response: ${JSON.stringify(data)}`);
  }

  return {
    ephemeralKey,
    expiresAt,
    raw: data,
    model
  };
}

function extractResponseText(data) {
  return (data?.output || [])
    .filter((item) => item?.type === 'message')
    .flatMap((item) => item.content || [])
    .filter((part) => part?.type === 'output_text' && typeof part.text === 'string')
    .map((part) => part.text)
    .join('\n')
    .trim();
}

const DEFAULT_SCENARIO_TEMPLATE = [
  'Create one complete interactive voice-performance scenario for The Phone application.',
  'Return only the scenario text. Do not use Markdown fences or add commentary.',
  'The output must use exactly this editable format:',
  'name: Scenario name',
  'voice: one of alloy, ash, ballad, coral, echo, marin, sage, shimmer, verse, cedar',
  '',
  '<BACKBONE>',
  'Global rules that apply throughout the entire experience.',
  '</BACKBONE>',
  '',
  '===PHASE===',
  'temperature: number from 0 to 1',
  'duration: positive number of assistant responses',
  'nudge: optional short trigger; omit the line when unnecessary',
  'instructions: phase instructions',
  '',
  'Repeat ===PHASE=== blocks as needed. Make every phase playable and ensure all user rules are reflected.'
].join('\n');

function parseVariableLists(text) {
  const lists = [];
  let current = null;

  for (const rawLine of text.replace(/\r\n?/g, '\n').split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;

    const heading = line.match(/^\d+\.\s+(.+)$/);
    if (heading) {
      current = { name: heading[1].trim(), values: [] };
      lists.push(current);
      continue;
    }
    if (!current) continue;

    const bullet = line.match(/^[-*]\s+(.+)$/);
    if (bullet) {
      current.values.push(bullet[1].trim());
      continue;
    }

    // Also handles compact prose such as "For each phase define: - A - B - C".
    const inlineValues = line.split(/\s+-\s+/).slice(1).map((value) => value.trim()).filter(Boolean);
    if (inlineValues.length) current.values.push(...inlineValues);
  }

  return lists.filter((list) => list.values.length > 0);
}

function buildVariableInstructions(variableListsText, requestedSelections = {}) {
  const lists = parseVariableLists(variableListsText);
  if (!lists.length) return { instructions: '', selections: {} };

  const selections = {};
  for (const list of lists) {
    const requested = typeof requestedSelections?.[list.name] === 'string'
      ? requestedSelections[list.name]
      : '__random__';
    const selected = requested !== '__random__' && list.values.includes(requested)
      ? requested
      : list.values[crypto.randomInt(list.values.length)];
    selections[list.name] = selected;
  }

  const formattedLists = lists
    .map((list) => `[${list.name}]\n${list.values.map((value) => `- ${value}`).join('\n')}`)
    .join('\n\n');

  const resolvedSelections = Object.entries(selections)
    .map(([name, value]) => `- ${name}: ${value}`)
    .join('\n');

  return {
    selections,
    instructions: [
    'VARIABLE-LIST REQUIREMENTS:',
    'Treat every numbered section below as one variable category and its bullets as available options or required fields.',
    'Use the resolved selection for every category. Random-mode choices have already been selected for this request.',
    'Inside <BACKBONE>, explicitly state the chosen Scenario Development Approach, all resolved General Scenario Variables, and the selected signs that make this unlike a typical AI conversation.',
    'Use one Conversation Opening Approach in the first phase.',
    'Use one or more Ways to Elicit a Response in every phase.',
    'Create exactly six ===PHASE=== blocks. In each phase instructions, explicitly define every item from the Six-Phase Command Template.',
    'The selected variables must actively affect the dialogue and progression, not appear as decorative metadata.',
    '',
    'RESOLVED VARIABLE SELECTIONS:',
    resolvedSelections,
    '',
    'AVAILABLE VARIABLE LISTS:',
    formattedLists
    ].join('\n')
  };
}

async function generateScenario(
  apiKey,
  rules,
  templatePrompt,
  variableListsText,
  requestedSelections,
  safetyIdentifier
) {
  const variableConfig = buildVariableInstructions(variableListsText, requestedSelections);
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'gpt-5.6-sol',
      reasoning: { effort: 'medium' },
      store: false,
      safety_identifier: safetyIdentifier,
      instructions: variableConfig.instructions
        ? `${templatePrompt}\n\n${variableConfig.instructions}`
        : templatePrompt,
      input: rules,
      max_output_tokens: 12000
    })
  });

  const rawText = await response.text();
  let data;
  try {
    data = rawText ? JSON.parse(rawText) : null;
  } catch (error) {
    throw new Error(`OpenAI returned non-JSON response: ${response.status}`);
  }

  if (!response.ok) {
    throw new Error(`OpenAI API error: ${response.status} - ${JSON.stringify(data)}`);
  }

  const scenario = extractResponseText(data);
  if (!scenario) throw new Error('OpenAI returned an empty scenario');

  return {
    scenario,
    responseId: data.id || null,
    usage: data.usage || null,
    variables: variableConfig.selections
  };
}

// ============================================
// ROUTES
// ============================================

app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'OpenAI Auth Gateway',
    version: '3.1.0',
    features: [
      'realtime-client-secrets',
      'ephemeral-keys',
      'multi-key-failover',
      'client-blacklist',
      'debug-details',
      'fixed-audio-output-voice'
    ],
    model: process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime-2.1',
    keysLoaded: keyPool.keys.length,
    healthyKeys: keyPool.getHealthyKeys().length,
    timestamp: new Date().toISOString()
  });
});

// 1️⃣ EPHEMERAL KEY FOR REALTIME API
app.post('/session', async (req, res) => {
  try {
    const {
      project,
      voice = 'shimmer',
      model = null,
      maxDuration = 300000,
      instructions = null
    } = req.body || {};

    const clientIp = req.ip || req.connection.remoteAddress;

    if (!project) {
      return res.status(400).json({
        error: 'Project ID required',
        code: 'MISSING_PROJECT'
      });
    }

    const normalizedModel = normalizeRealtimeModel(model);
    const normalizedVoice = normalizeVoice(voice);

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

    console.log(`🔑 Generating Realtime client secret for project: ${project}`);
    console.log(`🎙️ Voice: ${normalizedVoice}`);
    console.log(`🧠 Model: ${normalizedModel}`);
    console.log(`📊 Healthy keys: ${healthyKeys.length}/${keyPool.keys.length}`);

    let lastError = null;
    const maxAttempts = Math.min(6, healthyKeys.length);

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const apiKey = keyPool.getNextKey();
      const keyLabel = `${apiKey.substring(0, 10)}...${apiKey.substring(apiKey.length - 4)}`;

      try {
        console.log(`🔄 Attempt ${attempt + 1}/${maxAttempts} with key: ${keyLabel}`);

        const result = await createRealtimeClientSecret(apiKey, {
          voice: normalizedVoice,
          model: normalizedModel,
          instructions
        });

        keyPool.markKeySuccess(apiKey);

        console.log(`✅ Realtime client secret generated with ${keyLabel} on attempt ${attempt + 1}`);
        console.log(`⏳ Expires at: ${result.expiresAt || 'unknown'}`);

        return res.json({
          ephemeralKey: result.ephemeralKey,
          clientSecret: result.ephemeralKey,
          expiresAt: result.expiresAt,
          maxDuration,
          project,
          voice: normalizedVoice,
          model: result.model,
          rateLimit: {
            remaining: rateCheck.remaining,
            resetAt: rateCheck.resetAt
          },
          _meta: {
            keyUsed: keyLabel,
            attempt: attempt + 1,
            maxAttempts,
            healthyKeys: keyPool.getHealthyKeys().length,
            endpoint: '/v1/realtime/client_secrets'
          },
          ...(shouldExposeDebug(req)
            ? {
                _debug: {
                  openaiResponseShape: Object.keys(result.raw || {}),
                  rawOpenAIResponse: result.raw
                }
              }
            : {})
        });
      } catch (error) {
        lastError = error;

        console.error(`❌ Attempt ${attempt + 1} failed with key ${keyLabel}:`);
        console.error(error.message);

        keyPool.markKeyFailed(apiKey, error);

        if (attempt < maxAttempts - 1) {
          console.log('🔄 Trying next key...');
          continue;
        }
      }
    }

    console.error(`❌ All ${maxAttempts} failover attempts exhausted`);

    return res.status(503).json({
      error: `Failed to generate session key after ${maxAttempts} attempts`,
      code: 'ALL_KEYS_FAILED',
      details: lastError?.message || null,
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

// 2️⃣ SCENARIO GENERATOR (server-side Responses API; API key is never exposed)
app.post('/generate-scenario', async (req, res) => {
  const rules = typeof req.body?.rules === 'string' ? req.body.rules.trim() : '';
  const suppliedTemplate = typeof req.body?.templatePrompt === 'string'
    ? req.body.templatePrompt.trim()
    : '';
  const templatePrompt = suppliedTemplate || DEFAULT_SCENARIO_TEMPLATE;
  const variableListsText = typeof req.body?.variableLists === 'string'
    ? req.body.variableLists.trim()
    : '';
  const variableSelections = req.body?.variableSelections && typeof req.body.variableSelections === 'object'
    ? req.body.variableSelections
    : {};
  const clientIp = req.ip || req.connection.remoteAddress || 'unknown';

  if (!rules) {
    return res.status(400).json({ error: 'Generation rules are required', code: 'MISSING_RULES' });
  }
  if (rules.length > 20000) {
    return res.status(400).json({ error: 'Generation rules are too long', code: 'RULES_TOO_LONG' });
  }
  if (templatePrompt.length > 20000) {
    return res.status(400).json({ error: 'Template prompt is too long', code: 'TEMPLATE_TOO_LONG' });
  }
  if (variableListsText.length > 30000) {
    return res.status(400).json({ error: 'Variable lists are too long', code: 'VARIABLE_LISTS_TOO_LONG' });
  }

  const rateCheck = checkRateLimit(clientIp, 'scenario-generator');
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: rateCheck.message,
      code: 'RATE_LIMIT_EXCEEDED',
      resetIn: rateCheck.resetIn
    });
  }

  const healthyKeys = keyPool.getHealthyKeys();
  if (healthyKeys.length === 0) {
    return res.status(503).json({ error: 'No healthy API keys', code: 'NO_HEALTHY_KEYS' });
  }

  const safetyIdentifier = crypto
    .createHash('sha256')
    .update(`scenario-generator:${clientIp}`)
    .digest('hex');
  const maxAttempts = Math.min(3, healthyKeys.length);
  let lastError = null;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const apiKey = keyPool.getNextKey();
    try {
      const result = await generateScenario(
        apiKey,
        rules,
        templatePrompt,
        variableListsText,
        variableSelections,
        safetyIdentifier
      );
      keyPool.markKeySuccess(apiKey);
      return res.json({
        scenario: result.scenario,
        model: 'gpt-5.6-sol',
        responseId: result.responseId,
        usage: result.usage,
        variables: result.variables,
        rateLimit: { remaining: rateCheck.remaining, resetAt: rateCheck.resetAt }
      });
    } catch (error) {
      lastError = error;
      keyPool.markKeyFailed(apiKey, error);
      console.error(`❌ Scenario generation attempt ${attempt + 1} failed: ${error.message}`);
    }
  }

  return res.status(503).json({
    error: 'Scenario generation failed',
    code: 'GENERATION_FAILED',
    details: lastError?.message || null
  });
});

// 3️⃣ STANDARD API KEY
// Warning: this exposes a full OpenAI API key to the browser.
// Keep only for private debugging. Avoid for public production.
app.post('/api-key', async (req, res) => {
  try {
    const { project } = req.body || {};
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
      apiKey,
      keyLabel,
      project,
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

// 3️⃣ BLACKLIST KEY
app.post('/session/blacklist', (req, res) => {
  try {
    const { keyLabel, reason } = req.body || {};

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
        keyLabel
      });
    }

    res.json({
      success: true,
      message: 'Key blacklisted successfully',
      keyLabel,
      reason,
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

// 4️⃣ ANALYTICS
app.get('/analytics', (req, res) => {
  const stats = {
    activeRateLimitBuckets: rateLimitStore.size,
    timestamp: new Date().toISOString(),
    rateLimits: Array.from(rateLimitStore.entries()).map(([key, data]) => ({
      key,
      count: data.count,
      resetAt: new Date(data.resetAt).toISOString()
    }))
  };

  res.json(stats);
});

// 5️⃣ KEYS HEALTH
app.get('/keys/health', (req, res) => {
  const stats = keyPool.getStats();

  res.json({
    timestamp: new Date().toISOString(),
    summary: {
      total: stats.total,
      healthy: stats.healthy,
      unhealthy: stats.unhealthy,
      healthPercentage:
        stats.total > 0 ? ((stats.healthy / stats.total) * 100).toFixed(1) + '%' : '0%'
    },
    keys: stats.keys
  });
});

// 6️⃣ MANUAL HEALTH CHECK
app.post('/keys/check', async (req, res) => {
  const { adminKey } = req.body || {};

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({
      error: 'Unauthorized'
    });
  }

  console.log('🏥 Manual health check initiated...');

  const results = [];

  for (const key of keyPool.keys) {
    const keyLabel = `${key.substring(0, 10)}...${key.substring(key.length - 4)}`;

    try {
      const response = await fetch('https://api.openai.com/v1/models', {
        headers: {
          Authorization: `Bearer ${key}`
        }
      });

      const text = await response.text();
      const isHealthy = response.ok;

      const status = keyPool.keyStatus.get(key);
      status.healthy = isHealthy;
      status.lastCheck = Date.now();
      status.lastError = isHealthy ? null : `HTTP ${response.status}: ${text}`;

      if (isHealthy) {
        status.failCount = 0;
      }

      results.push({
        key: keyLabel,
        status: isHealthy ? 'healthy' : 'unhealthy',
        httpStatus: response.status,
        details: isHealthy ? undefined : text
      });

      console.log(`${isHealthy ? '✅' : '❌'} ${keyLabel}: ${response.status}`);
    } catch (error) {
      const status = keyPool.keyStatus.get(key);
      status.healthy = false;
      status.lastCheck = Date.now();
      status.lastError = error.message;

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
    results,
    summary: keyPool.getStats()
  });
});

// 7️⃣ RECOVER KEY
app.post('/keys/recover', async (req, res) => {
  const { adminKey, keyIndex } = req.body || {};

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({
      error: 'Unauthorized'
    });
  }

  if (
    typeof keyIndex !== 'number' ||
    keyIndex < 0 ||
    keyIndex >= keyPool.keys.length
  ) {
    return res.status(400).json({
      error: 'Invalid key index'
    });
  }

  const key = keyPool.keys[keyIndex];
  const status = keyPool.keyStatus.get(key);

  status.failCount = 0;
  status.healthy = true;
  status.lastCheck = Date.now();
  status.lastError = null;

  console.log(`🔄 Key ${keyIndex} manually recovered`);

  res.json({
    message: 'Key recovered',
    keyIndex,
    status
  });
});

// 8️⃣ RESET RATE LIMITS
app.post('/admin/reset-limits', (req, res) => {
  const { adminKey } = req.body || {};

  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({
      error: 'Unauthorized'
    });
  }

  rateLimitStore.clear();
  console.log('🔄 Rate limits cleared by admin');

  res.json({
    success: true,
    message: 'All rate limits cleared'
  });
});

// ============================================
// 404 + ERROR HANDLER
// ============================================

app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /',
      'POST /session',
      'POST /generate-scenario',
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

// ============================================
// START
// ============================================

app.listen(PORT, () => {
  console.log('🚀 OpenAI Auth Gateway v3.1 - Realtime client_secrets');
  console.log(`📡 Server running on port ${PORT}`);
  console.log(`🔑 API Keys loaded: ${keyPool.keys.length}`);
  console.log(`✅ Healthy keys: ${keyPool.getHealthyKeys().length}`);
  console.log(`🧠 Realtime model: ${process.env.OPENAI_REALTIME_MODEL || 'gpt-realtime-2.1'}`);
  console.log(`🛡️ CORS enabled for: ${allowedOrigins.join(', ')}`);
  console.log(`⏰ Time: ${new Date().toISOString()}`);

  console.log('\n📊 Endpoints:');
  console.log('   GET  /                       - Service status');
  console.log('   POST /session                - Generate Realtime ephemeral key');
  console.log('   POST /generate-scenario      - Generate scenario with GPT-5.6 Sol');
  console.log('   POST /api-key                - Get standard API key');
  console.log('   POST /session/blacklist      - Blacklist bad key');
  console.log('   GET  /analytics              - Rate limit stats');
  console.log('   GET  /keys/health            - API keys health status');
  console.log('   POST /keys/check             - Manual health check');
  console.log('   POST /keys/recover           - Recover specific key');
  console.log('   POST /admin/reset-limits     - Reset rate limits');
});

process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Promise Rejection:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
});
