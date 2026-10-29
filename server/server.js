require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const { PDFParse } = require('pdf-parse');
const mammoth = require('mammoth');
const { MsEdgeTTS, OUTPUT_FORMAT } = require('msedge-tts');

const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'studycast-dev-secret-troque-antes-de-publicar',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 } // sessao dura 30 dias
}));
app.use(express.static(path.join(__dirname, '..')));

// ---------- autenticacao (cadastro/login de usuarios) ----------
const USERS_FILE = path.join(__dirname, 'users.json');

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function writeUsers(list) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(list, null, 2));
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, plan: u.plan, studyMinutes: u.studyMinutes || 0, isAdmin: !!u.isAdmin };
}

// soma minutos de estudo "de verdade" toda vez que a pessoa usa algo (chat, explicacao, audio, material novo)
function addStudyMinutes(userId, minutes) {
  const users = readUsers();
  const user = users.find(u => u.id === userId);
  if (!user) return;
  user.studyMinutes = (user.studyMinutes || 0) + minutes;
  writeUsers(users);
}

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !name.trim() || !email || !password) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'password_too_short' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const users = readUsers();
  if (users.some(u => u.email === normalizedEmail)) {
    return res.status(409).json({ error: 'email_taken' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now(),
    name: name.trim(),
    email: normalizedEmail,
    passwordHash,
    plan: 'free',
    studyMinutes: 0,
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeUsers(users);
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = (email || '').trim().toLowerCase();
  const users = readUsers();
  const user = users.find(u => u.email === normalizedEmail);
  if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  res.json({ user: publicUser(user) });
});

// codigo de administrador validado so aqui no servidor (nunca exposto no JS do navegador)
app.post('/api/auth/admin', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  const { code } = req.body;
  if (!process.env.ADMIN_CODE || code !== process.env.ADMIN_CODE) {
    return res.status(403).json({ error: 'wrong_code' });
  }
  user.isAdmin = true;
  writeUsers(users);
  res.json({ user: publicUser(user) });
});
app.post('/api/auth/admin/deactivate', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  user.isAdmin = false;
  writeUsers(users);
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/plan', (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  const { plan } = req.body;
  if (!['free', 'plus', 'premium'].includes(plan)) {
    return res.status(400).json({ error: 'invalid_plan' });
  }
  user.plan = plan;
  writeUsers(users);
  res.json({ user: publicUser(user) });
});

const FEEDBACK_FILE = path.join(__dirname, 'feedback.json');

function readFeedback() {
  try {
    return JSON.parse(fs.readFileSync(FEEDBACK_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function writeFeedback(list) {
  fs.writeFileSync(FEEDBACK_FILE, JSON.stringify(list, null, 2));
}

app.post('/api/feedback', (req, res) => {
  const { name, rating, message, lang } = req.body;
  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'message_required' });
  }
  const entry = {
    id: Date.now(),
    name: (name || '').trim() || (lang === 'pt' ? 'Anônimo' : 'Anonymous'),
    rating: Number(rating) || 0,
    message: message.trim(),
    date: new Date().toISOString()
  };
  const list = readFeedback();
  list.unshift(entry);
  writeFeedback(list);
  res.json({ ok: true });
});

// visite http://localhost:3000/api/feedback no navegador pra ver tudo que foi enviado
app.get('/api/feedback', (req, res) => {
  res.json(readFeedback());
});

// ---------- processar PDF/DOCX/TXT enviados (extrai o texto de verdade) ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 } // 20MB
});

app.post('/api/parse-file', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'file_required' });
  }
  const name = req.file.originalname || '';
  const ext = name.split('.').pop().toLowerCase();

  try {
    let text = '';
    if (ext === 'pdf') {
      const parser = new PDFParse({ data: req.file.buffer });
      const result = await parser.getText();
      await parser.destroy();
      text = result.text;
    } else if (ext === 'docx') {
      const result = await mammoth.extractRawText({ buffer: req.file.buffer });
      text = result.value;
    } else if (ext === 'doc') {
      return res.status(415).json({ error: 'doc_unsupported' });
    } else if (ext === 'txt') {
      text = req.file.buffer.toString('utf8');
    } else {
      return res.status(415).json({ error: 'unsupported_type' });
    }

    text = text.replace(/\r\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();

    // PDF escaneado (so imagem, sem texto real) -> erro claro em vez de mandar
    // um texto vazio/quase vazio pra IA gerar conteudo do nada. OCR nao entra agora.
    if (ext === 'pdf' && text.length < 20) {
      return res.status(422).json({ error: 'pdf_no_text' });
    }

    res.json({ text });
  } catch (err) {
    console.error('parse-file error:', err.message);
    res.status(500).json({ error: 'parse_failed' });
  }
});

const GEMINI_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = 'gemini-flash-latest';
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_KEY}`;

const GROQ_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = 'openai/gpt-oss-120b';
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_MODEL = 'minimax/minimax-m2.7:free';
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

const CLOUDFLARE_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CLOUDFLARE_MODEL = '@cf/meta/llama-3.1-8b-instruct';
const CLOUDFLARE_URL = CLOUDFLARE_ACCOUNT_ID
  ? `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai/run/${CLOUDFLARE_MODEL}`
  : null;

// desiste de uma IA lenta/travada depois de 15s, pra cair pra proxima da fila
// em vez de deixar o usuario esperando minutos.
const AI_TIMEOUT_MS = 15000;
async function fetchWithTimeout(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function callGemini(systemInstruction, contents) {
  const response = await fetchWithTimeout(GEMINI_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemInstruction }] },
      contents
    })
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error?.message || 'Gemini API error');
  }
  const parts = data.candidates?.[0]?.content?.parts || [];
  return parts.map(p => p.text || '').join('\n').trim();
}

// Groq = respostas rapidas pro chat. Se a chave nao estiver configurada, ou a
// chamada falhar (limite atingido, fora do ar etc.), caimos pro Gemini como plano B.
async function callGroq(systemInstruction, messages) {
  if (!GROQ_KEY) throw new Error('Groq nao configurado');
  const response = await fetchWithTimeout(GROQ_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${GROQ_KEY}`
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [{ role: 'system', content: systemInstruction }, ...messages]
    })
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error?.message || 'Groq API error');
  }
  return (data.choices?.[0]?.message?.content || '').trim();
}

// OpenRouter = backup gratuito extra, usado so quando Groq e Gemini falham os dois.
async function callOpenRouter(systemInstruction, messages) {
  if (!OPENROUTER_KEY) throw new Error('OpenRouter nao configurado');
  const response = await fetchWithTimeout(OPENROUTER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENROUTER_KEY}`
    },
    body: JSON.stringify({
      model: OPENROUTER_MODEL,
      messages: [{ role: 'system', content: systemInstruction }, ...messages]
    })
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.error?.message || 'OpenRouter API error');
  }
  return (data.choices?.[0]?.message?.content || '').trim();
}

// Cloudflare Workers AI = quarta camada de apoio, usada so quando Groq, Gemini
// e OpenRouter falham todos. Backend confiavel (Cloudflare), tier gratuito diario.
async function callCloudflare(systemInstruction, messages) {
  if (!CLOUDFLARE_URL || !CLOUDFLARE_API_TOKEN) throw new Error('Cloudflare nao configurado');
  const response = await fetchWithTimeout(CLOUDFLARE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN}`
    },
    body: JSON.stringify({
      messages: [{ role: 'system', content: systemInstruction }, ...messages]
    })
  });
  const data = await response.json();
  if (!response.ok || !data.success) {
    throw new Error(data?.errors?.[0]?.message || 'Cloudflare Workers AI error');
  }
  return (data.result?.response || data.result?.choices?.[0]?.message?.content || '').trim();
}

// tenta cada IA gratuita em ordem ate uma responder; so devolve erro se todas falharem
// manda alerta no maximo 1x a cada 15min, mesmo que todo mundo continue falhando —
// evita encher o log/webhook de alertas repetidos enquanto o problema persiste.
let lastAllAiAlertAt = 0;
const ALL_AI_ALERT_COOLDOWN_MS = 15 * 60 * 1000;

async function withFallback(attempts, context) {
  let lastError;
  for (const { name, run } of attempts) {
    try {
      const text = await run();
      return { text, model: name };
    } catch (err) {
      console.error(`${name} falhou:`, err.message);
      lastError = err;
    }
  }
  const now = Date.now();
  if (now - lastAllAiAlertAt > ALL_AI_ALERT_COOLDOWN_MS) {
    lastAllAiAlertAt = now;
    alertFounder(`As 4 IAs de texto falharam todas${context ? ` (${context})` : ''}! Último erro: ${lastError?.message || 'desconhecido'}.`);
  }
  throw lastError;
}

app.post('/api/chat', async (req, res) => {
  const { messages = [], lang = 'pt' } = req.body;
  const systemInstruction = lang === 'pt'
    ? 'Você é o assistente de estudos do Studycast AI. Responda em português do Brasil, de forma clara, didática e objetiva, ajudando o usuário a entender melhor o conteúdo que está estudando. Seja encorajador mas direto.'
    : 'You are the Studycast AI study assistant. Reply in English, clearly and didactically, helping the user better understand the content they are studying. Be encouraging but direct.';

  const openAiStyleMessages = messages.map(m => ({ role: m.role, content: m.content }));
  const geminiContents = messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }]
  }));

  try {
    const { text, model } = await withFallback([
      { name: 'groq', run: () => callGroq(systemInstruction, openAiStyleMessages) },
      { name: 'gemini', run: () => callGemini(systemInstruction, geminiContents) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, openAiStyleMessages) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, openAiStyleMessages) }
    ], 'chat');
    if (req.session.userId) addStudyMinutes(req.session.userId, 1);
    res.json({ reply: text, model });
  } catch (err) {
    console.error('chat error (todas as IAs falharam):', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/explain', async (req, res) => {
  const { title, goal, lang = 'pt' } = req.body;
  const systemInstruction = lang === 'pt'
    ? 'Você é o Studycast AI. Escreva, em português do Brasil, uma explicação completa e didática sobre o tema do material informado, cobrindo o máximo possível do que for relevante para o objetivo de estudo indicado: conceitos centrais, pontos que costumam confundir os estudantes, e conexões com temas relacionados. Organize em parágrafos curtos e claros. Não use markdown (sem #, sem **); escreva em texto corrido, um parágrafo por linha.'
    : 'You are Studycast AI. Write, in English, a complete and didactic explanation about the topic of the given material, covering as much as possible of what is relevant for the stated study goal: core concepts, common points of confusion, and connections to related topics. Organize into short, clear paragraphs. Do not use markdown (no #, no **); write in plain prose, one paragraph per line.';

  const userPrompt = lang === 'pt'
    ? `Material: "${title}"\nObjetivo de estudo: ${goal}\n\nExplique o máximo possível sobre esse tema.`
    : `Material: "${title}"\nStudy goal: ${goal}\n\nExplain as much as possible about this topic.`;

  try {
    const { text, model } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'explain');
    res.json({ explanation: text, model });
  } catch (err) {
    console.error('explain error (todas as IAs falharam):', err.message);
    res.status(500).json({ error: err.message });
  }
});

// extrai o primeiro array JSON valido de um texto, ignorando markdown/texto ao redor
// que os modelos as vezes adicionam mesmo quando pedimos "so JSON".
function extractJsonArray(text) {
  const start = text.indexOf('[');
  const end = text.lastIndexOf(']');
  if (start === -1 || end === -1 || end < start) {
    throw new Error('no_json_found');
  }
  return JSON.parse(text.slice(start, end + 1));
}
function extractJsonObject(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) {
    throw new Error('no_json_found');
  }
  return JSON.parse(text.slice(start, end + 1));
}

// ---------- materiais reais do usuario (upload -> resumo/flashcards/mapa mental de verdade) ----------
const MATERIALS_FILE = path.join(__dirname, 'materials.json');

function readMaterials() {
  try {
    return JSON.parse(fs.readFileSync(MATERIALS_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function writeMaterials(list) {
  fs.writeFileSync(MATERIALS_FILE, JSON.stringify(list, null, 2));
}

function requireAuth(req, res) {
  const users = readUsers();
  const user = users.find(u => u.id === req.session.userId);
  if (!user) {
    res.status(401).json({ error: 'not_authenticated' });
    return null;
  }
  return user;
}

app.get('/api/materials', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const mine = readMaterials().filter(m => m.userId === user.id).sort((a, b) => b.id - a.id);
  res.json({ materials: mine });
});

app.post('/api/materials', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const { title, type, sourceText, goal, lang = 'pt' } = req.body;
  if (!title || !sourceText || !sourceText.trim()) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  const studyGoal = goal || (lang === 'pt' ? 'Estudo pessoal' : 'Personal study');

  const systemInstruction = lang === 'pt'
    ? 'Você é o Studycast AI. A partir do texto de material de estudo fornecido, gere um título curto e descritivo pra esse material (baseado no conteúdo, não no nome do arquivo), um resumo em tópicos, de 4 a 6 flashcards de pergunta e resposta, e 5 rótulos curtos para um mapa mental dos conceitos principais. Responda APENAS com um JSON válido, sem texto antes ou depois, sem markdown e sem crases, exatamente neste formato: {"title":"título curto e descritivo do tema","resumo":["ponto 1, pode usar <strong>negrito</strong> para destacar termos-chave","ponto 2"],"flashcards":[{"q":"pergunta","a":"resposta"}],"mindmap":["rótulo curto 1","rótulo curto 2"]}. Foque no que for mais relevante para o objetivo de estudo indicado.'
    : 'You are Studycast AI. From the given study material text, generate a short, descriptive title for this material (based on the content, not the file name), a bullet-point summary, 4 to 6 question-and-answer flashcards, and 5 short labels for a mind map of the main concepts. Respond ONLY with valid JSON, no text before or after, no markdown, no backticks, in exactly this format: {"title":"short descriptive title of the topic","resumo":["point 1, can use <strong>bold</strong> for key terms","point 2"],"flashcards":[{"q":"question","a":"answer"}],"mindmap":["short label 1","short label 2"]}. Focus on what is most relevant for the stated study goal.';

  const userPrompt = lang === 'pt'
    ? `Nome do arquivo enviado: "${title}"\nObjetivo de estudo: ${studyGoal}\n\nTexto do material:\n${sourceText.slice(0, 6000)}\n\nGere o título, o resumo, os flashcards e o mapa mental.`
    : `Uploaded file name: "${title}"\nStudy goal: ${studyGoal}\n\nMaterial text:\n${sourceText.slice(0, 6000)}\n\nGenerate the title, summary, flashcards and mind map.`;

  try {
    const { text } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'criação de material');
    const generated = extractJsonObject(text);

    const material = {
      id: Date.now(),
      userId: user.id,
      title: (generated.title && generated.title.trim()) || title,
      type: type || 'Arquivo',
      goal: studyGoal,
      date: new Date().toISOString(),
      sourceText: sourceText.slice(0, 8000),
      resumo: Array.isArray(generated.resumo) ? generated.resumo : [],
      flashcards: Array.isArray(generated.flashcards) ? generated.flashcards : [],
      mindmap: Array.isArray(generated.mindmap) ? generated.mindmap : [],
      explanation: null
    };
    const list = readMaterials();
    list.push(material);
    writeMaterials(list);
    addStudyMinutes(user.id, 5);

    res.json({ material });
  } catch (err) {
    console.error('materials error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/materials/:id/explain', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const { lang = 'pt' } = req.body;
  const list = readMaterials();
  const material = list.find(m => m.id === Number(req.params.id) && m.userId === user.id);
  if (!material) return res.status(404).json({ error: 'not_found' });

  if (material.explanation) {
    return res.json({ explanation: material.explanation });
  }

  const systemInstruction = lang === 'pt'
    ? 'Você é o Studycast AI. Com base no texto de material de estudo fornecido, escreva, em português do Brasil, uma explicação completa e didática sobre o tema, cobrindo o máximo possível do que for relevante para o objetivo de estudo indicado: conceitos centrais, pontos que costumam confundir os estudantes, e conexões com temas relacionados. Organize em parágrafos curtos e claros. Não use markdown (sem #, sem **); escreva em texto corrido, um parágrafo por linha.'
    : 'You are Studycast AI. Based on the given study material text, write, in English, a complete and didactic explanation about the topic, covering as much as possible of what is relevant for the stated study goal: core concepts, common points of confusion, and connections to related topics. Organize into short, clear paragraphs. Do not use markdown (no #, no **); write in plain prose, one paragraph per line.';

  const userPrompt = lang === 'pt'
    ? `Material: "${material.title}"\nObjetivo de estudo: ${material.goal}\n\nTexto do material:\n${material.sourceText || '(texto original não disponível, use o título e o objetivo)'}\n\nExplique o máximo possível sobre esse tema.`
    : `Material: "${material.title}"\nStudy goal: ${material.goal}\n\nMaterial text:\n${material.sourceText || '(original text unavailable, use the title and goal)'}\n\nExplain as much as possible about this topic.`;

  try {
    const { text } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'explicação de material');
    material.explanation = text;
    writeMaterials(list);
    addStudyMinutes(user.id, 8);
    res.json({ explanation: text });
  } catch (err) {
    console.error('material explain error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/stats', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const mine = readMaterials().filter(m => m.userId === user.id);
  const contentGenerated = mine.reduce((sum, m) => {
    let count = 0;
    if (m.resumo && m.resumo.length) count++;
    if (m.flashcards && m.flashcards.length) count++;
    if (m.mindmap && m.mindmap.length) count++;
    if (m.explanation) count++;
    return sum + count;
  }, 0);
  res.json({
    documentsCount: mine.length,
    materialsProcessed: mine.length,
    contentGenerated,
    studyMinutes: user.studyMinutes || 0
  });
});

app.post('/api/schedule', async (req, res) => {
  const { tasks, availability, lang = 'pt' } = req.body;
  if (!tasks || !tasks.trim() || !availability || !availability.trim()) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  const systemInstruction = lang === 'pt'
    ? 'Você é o Studycast AI. Sua tarefa é criar um cronograma semanal de estudos com base nas tarefas e nos horários livres informados pelo usuário. Responda APENAS com um JSON válido, sem nenhum texto antes ou depois, sem markdown e sem crases, exatamente neste formato: [{"day":"Segunda","blocks":[{"time":"19:00 - 20:00","activity":"descrição curta da atividade"}]},{"day":"Terça","blocks":[]}]. Inclua sempre os 7 dias da semana, de Segunda a Domingo, nessa ordem, mesmo que algum dia fique com a lista de blocks vazia. Distribua as tarefas do usuário de forma equilibrada dentro dos horários livres informados, com atividades específicas e realistas (nada de "estudar" genérico — diga o quê estudar, com base no que foi pedido).'
    : 'You are Studycast AI. Your task is to build a weekly study schedule based on the tasks and free time slots given by the user. Respond ONLY with valid JSON, no text before or after, no markdown, no backticks, in exactly this format: [{"day":"Monday","blocks":[{"time":"7:00 PM - 8:00 PM","activity":"short activity description"}]},{"day":"Tuesday","blocks":[]}]. Always include all 7 days of the week, Monday through Sunday, in that order, even if some day ends up with an empty blocks list. Distribute the user\'s tasks evenly across the free time slots given, with specific, realistic activities (nothing generic like "study" — say what to study, based on what was requested).';

  const userPrompt = lang === 'pt'
    ? `Tarefas e coisas que preciso fazer essa semana: ${tasks}\n\nHorários que tenho livre: ${availability}\n\nMonte meu cronograma semanal.`
    : `Tasks and things I need to do this week: ${tasks}\n\nTimes I'm free: ${availability}\n\nBuild my weekly schedule.`;

  try {
    const { text } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'cronograma');
    const schedule = extractJsonArray(text);
    res.json({ schedule });
  } catch (err) {
    console.error('schedule error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ================= TTS (audio) — geracao com cache, cota e trava de custo =================
// Provedor: Edge-TTS (voz neural da Microsoft, gratuito, sem chave/cartao). O restante da
// arquitetura (cache por hash, cota mensal por usuario, kill switch global, chunking,
// rate limit) segue o briefing tecnico do audio.
const TTS_VOICES = {
  pt: 'pt-BR-FranciscaNeural',
  en: 'en-US-JennyNeural'
};

const TTS_GLOBAL_MONTHLY_CHAR_CAP = Number(process.env.TTS_GLOBAL_MONTHLY_CHAR_CAP || 3000000);
const TTS_FREE_PLAN_CHAR_LIMIT = Number(process.env.TTS_FREE_PLAN_CHAR_LIMIT || 13500);
const TTS_PLUS_PLAN_CHAR_LIMIT = Number(process.env.TTS_PLUS_PLAN_CHAR_LIMIT || 270000); // Estudante: 5h/mes
const TTS_PREMIUM_PLAN_CHAR_LIMIT = Number(process.env.TTS_PREMIUM_PLAN_CHAR_LIMIT || 540000); // Premium: 10h/mes

function planCharLimit(plan) {
  if (plan === 'free') return TTS_FREE_PLAN_CHAR_LIMIT;
  if (plan === 'plus') return TTS_PLUS_PLAN_CHAR_LIMIT;
  return TTS_PREMIUM_PLAN_CHAR_LIMIT;
}
const TTS_RATE_LIMIT_PER_HOUR = Number(process.env.TTS_RATE_LIMIT_PER_HOUR || 5);
const TTS_MAX_DOCUMENT_CHARS = Number(process.env.TTS_MAX_DOCUMENT_CHARS || 200000);

const AUDIO_CACHE_DIR = path.join(__dirname, 'audio-cache');
if (!fs.existsSync(AUDIO_CACHE_DIR)) fs.mkdirSync(AUDIO_CACHE_DIR, { recursive: true });

const AUDIOS_FILE = path.join(__dirname, 'audios.json');
const AUDIO_USAGE_FILE = path.join(__dirname, 'audio-usage-monthly.json');
const TTS_GLOBAL_USAGE_FILE = path.join(__dirname, 'tts-global-usage.json');
const ALERTS_FILE = path.join(__dirname, 'alerts.log');

function readJsonFile(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJsonFile(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function currentYearMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function getUserMonthlyChars(userId) {
  const usage = readJsonFile(AUDIO_USAGE_FILE, {});
  return (usage[userId] && usage[userId][currentYearMonth()]) || 0;
}
function addUserMonthlyChars(userId, chars) {
  const usage = readJsonFile(AUDIO_USAGE_FILE, {});
  const ym = currentYearMonth();
  if (!usage[userId]) usage[userId] = {};
  usage[userId][ym] = (usage[userId][ym] || 0) + chars;
  writeJsonFile(AUDIO_USAGE_FILE, usage);
  return usage[userId][ym];
}
function getGlobalMonthlyChars() {
  const usage = readJsonFile(TTS_GLOBAL_USAGE_FILE, {});
  return usage[currentYearMonth()] || 0;
}
function addGlobalMonthlyChars(chars) {
  const usage = readJsonFile(TTS_GLOBAL_USAGE_FILE, {});
  const ym = currentYearMonth();
  usage[ym] = (usage[ym] || 0) + chars;
  writeJsonFile(TTS_GLOBAL_USAGE_FILE, usage);
  return usage[ym];
}

// registra num arquivo de log + console (e num webhook, se FOUNDER_ALERT_WEBHOOK estiver
// configurado) — "melhor o app parar do que gerar fatura surpresa".
function alertFounder(message) {
  fs.appendFileSync(ALERTS_FILE, `[${new Date().toISOString()}] ${message}\n`);
  console.error('🚨 ALERTA FUNDADOR:', message);
  if (process.env.FOUNDER_ALERT_WEBHOOK) {
    fetch(process.env.FOUNDER_ALERT_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: `Studycast AI — ${message}` })
    }).catch(err => console.error('falha ao enviar alerta pro webhook:', err.message));
  }
}

// rate limit por usuario (em memoria — reseta se o servidor reiniciar, o que aqui é aceitavel)
const ttsRequestLog = new Map();
function isRateLimited(userId) {
  const hourAgo = Date.now() - 60 * 60 * 1000;
  const timestamps = (ttsRequestLog.get(userId) || []).filter(t => t > hourAgo);
  ttsRequestLog.set(userId, timestamps);
  return timestamps.length >= TTS_RATE_LIMIT_PER_HOUR;
}
function logTtsRequest(userId) {
  const timestamps = ttsRequestLog.get(userId) || [];
  timestamps.push(Date.now());
  ttsRequestLog.set(userId, timestamps);
}

// normalizacao leve: colapsa espacos/linhas em excesso, remove linhas que sao so um numero
// solto (resquicio de numero de pagina de PDF).
function normalizeTtsText(text) {
  return text
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter(line => !/^\s*\d{1,4}\s*$/.test(line))
    .join('\n')
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// corta o texto em blocos respeitando fim de frase/paragrafo, nunca no meio de palavra
function chunkText(text, maxChars) {
  if (text.length <= maxChars) return [text];
  const chunks = [];
  let remaining = text;
  while (remaining.length > maxChars) {
    let cut = remaining.lastIndexOf('\n\n', maxChars);
    if (cut < maxChars * 0.5) cut = remaining.lastIndexOf('. ', maxChars);
    if (cut < maxChars * 0.5) cut = remaining.lastIndexOf(' ', maxChars);
    if (cut < 1) cut = maxChars;
    chunks.push(remaining.slice(0, cut + 1).trim());
    remaining = remaining.slice(cut + 1);
  }
  if (remaining.trim()) chunks.push(remaining.trim());
  return chunks;
}

function synthesizeChunk(text, voice) {
  return new Promise((resolve, reject) => {
    (async () => {
      try {
        const tts = new MsEdgeTTS();
        await tts.setMetadata(voice, OUTPUT_FORMAT.AUDIO_24KHZ_48KBITRATE_MONO_MP3);
        const { audioStream } = tts.toStream(text);
        const parts = [];
        audioStream.on('data', (c) => parts.push(c));
        audioStream.on('end', () => resolve(Buffer.concat(parts)));
        audioStream.on('error', reject);
      } catch (err) {
        reject(err);
      }
    })();
  });
}
async function synthesizeFull(text, voice) {
  const chunks = chunkText(text, 3000);
  const buffers = [];
  for (const chunk of chunks) {
    buffers.push(await synthesizeChunk(chunk, voice));
  }
  return Buffer.concat(buffers);
}

app.get('/api/tts/usage', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const limit = planCharLimit(user.plan);
  const used = getUserMonthlyChars(user.id);
  res.json({
    isAdmin: !!user.isAdmin,
    charsUsed: used,
    charLimit: limit,
    minutesUsed: Math.round(used / 900),
    minutesLimit: Math.round(limit / 900),
    percent: user.isAdmin ? 0 : Math.min(100, Math.round((used / limit) * 100))
  });
});

app.post('/api/tts', async (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;

  const { text: rawText, lang = 'pt' } = req.body;
  if (!rawText || !rawText.trim()) {
    return res.status(400).json({ error: 'text_required' });
  }

  const text = normalizeTtsText(rawText);
  const charCount = text.length;

  if (charCount > TTS_MAX_DOCUMENT_CHARS) {
    return res.status(413).json({ error: 'document_too_large', maxChars: TTS_MAX_DOCUMENT_CHARS });
  }

  const voice = TTS_VOICES[lang] || TTS_VOICES.pt;
  const hash = crypto.createHash('sha256').update(`${text}|${voice}`).digest('hex');
  const cacheFile = path.join(AUDIO_CACHE_DIR, `${hash}.mp3`);

  try {
    let buffer;

    if (fs.existsSync(cacheFile)) {
      // cache hit: nao gera de novo, nao conta cota, nao passa pelo rate limit
      buffer = fs.readFileSync(cacheFile);
    } else {
      if (!user.isAdmin) {
        if (isRateLimited(user.id)) {
          return res.status(429).json({ error: 'rate_limited', limitPerHour: TTS_RATE_LIMIT_PER_HOUR });
        }
        const globalUsed = getGlobalMonthlyChars();
        if (globalUsed >= TTS_GLOBAL_MONTHLY_CHAR_CAP) {
          alertFounder(`Kill switch de TTS ativado! Uso global do mês: ${globalUsed} caracteres (teto: ${TTS_GLOBAL_MONTHLY_CHAR_CAP}).`);
          return res.status(503).json({ error: 'global_cap_reached' });
        }
        const planLimit = planCharLimit(user.plan);
        const userUsed = getUserMonthlyChars(user.id);
        if (userUsed + charCount > planLimit) {
          return res.status(402).json({ error: 'quota_exceeded', charsUsed: userUsed, charLimit: planLimit });
        }
        logTtsRequest(user.id);
      }
      buffer = await synthesizeFull(text, voice);
      fs.writeFileSync(cacheFile, buffer);

      const audios = readJsonFile(AUDIOS_FILE, []);
      audios.push({
        id: Date.now(),
        userId: user.id,
        contentHash: hash,
        storageFile: `${hash}.mp3`,
        durationSeconds: Math.round(buffer.length / 6000),
        charCount,
        voice,
        provider: 'edge-tts',
        createdAt: new Date().toISOString()
      });
      writeJsonFile(AUDIOS_FILE, audios);

      if (!user.isAdmin) {
        addUserMonthlyChars(user.id, charCount);
        const newGlobal = addGlobalMonthlyChars(charCount);
        if (newGlobal >= TTS_GLOBAL_MONTHLY_CHAR_CAP) {
          alertFounder(`Kill switch de TTS ativado! Uso global do mês: ${newGlobal} caracteres (teto: ${TTS_GLOBAL_MONTHLY_CHAR_CAP}).`);
        } else if (newGlobal >= TTS_GLOBAL_MONTHLY_CHAR_CAP * 0.8) {
          alertFounder(`Aviso: uso global de TTS em ${Math.round((newGlobal / TTS_GLOBAL_MONTHLY_CHAR_CAP) * 100)}% do teto mensal (${newGlobal}/${TTS_GLOBAL_MONTHLY_CHAR_CAP} chars).`);
        }
      }
    }

    // minutos de estudo contam mesmo em cache hit — a pessoa esta ouvindo de verdade
    const minutes = Math.max(1, Math.round(buffer.length / 6000 / 60));
    addStudyMinutes(user.id, minutes);

    res.setHeader('Content-Type', 'audio/mpeg');
    res.end(buffer);
  } catch (err) {
    console.error('tts error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Studycast AI server rodando em http://localhost:${PORT}`);
});
