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
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'studycast-dev-secret-troque-antes-de-publicar',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 } // sessao dura 30 dias
}));
app.use(express.static(path.join(__dirname, '..')));

// ---------- banco de dados (Supabase/Postgres) — usuarios, materiais, quizzes e feedback ----------
// so persiste aqui o que nao pode se perder (contas, materiais, provas). O cache de audio e os
// contadores de cota de TTS continuam em arquivo local: perder isso so custa regenerar audio,
// nao e grave como perder a conta ou o material de alguem.
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    passwordHash: row.password_hash,
    plan: row.plan,
    studyMinutes: row.study_minutes || 0,
    isAdmin: !!row.is_admin,
    createdAt: row.created_at
  };
}
function userToRow(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    password_hash: u.passwordHash,
    plan: u.plan,
    study_minutes: u.studyMinutes || 0,
    is_admin: !!u.isAdmin,
    created_at: u.createdAt
  };
}
async function findUserById(id) {
  if (!id) return null;
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return rowToUser(data);
}
async function findUserByEmail(email) {
  const { data, error } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
  if (error) throw error;
  return rowToUser(data);
}
async function insertUser(user) {
  const { data, error } = await supabase.from('users').insert(userToRow(user)).select().single();
  if (error) throw error;
  return rowToUser(data);
}
async function updateUser(id, fields) {
  const row = {};
  if ('plan' in fields) row.plan = fields.plan;
  if ('isAdmin' in fields) row.is_admin = fields.isAdmin;
  if ('studyMinutes' in fields) row.study_minutes = fields.studyMinutes;
  const { error } = await supabase.from('users').update(row).eq('id', id);
  if (error) throw error;
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, plan: u.plan, studyMinutes: u.studyMinutes || 0, isAdmin: !!u.isAdmin };
}

// soma minutos de estudo "de verdade" toda vez que a pessoa usa algo (chat, explicacao, audio, material novo)
async function addStudyMinutes(userId, minutes) {
  const user = await findUserById(userId);
  if (!user) return;
  await updateUser(userId, { studyMinutes: (user.studyMinutes || 0) + minutes });
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
  try {
    if (await findUserByEmail(normalizedEmail)) {
      return res.status(409).json({ error: 'email_taken' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await insertUser({
      id: Date.now(),
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      plan: 'free',
      studyMinutes: 0,
      isAdmin: false,
      createdAt: new Date().toISOString()
    });
    req.session.userId = user.id;
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error('signup error:', err.message);
    res.status(500).json({ error: 'signup_failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = (email || '').trim().toLowerCase();
  try {
    const user = await findUserByEmail(normalizedEmail);
    if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    req.session.userId = user.id;
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(500).json({ error: 'login_failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', async (req, res) => {
  const user = await findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  res.json({ user: publicUser(user) });
});

// codigo de administrador validado so aqui no servidor (nunca exposto no JS do navegador)
app.post('/api/auth/admin', async (req, res) => {
  const user = await findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  const { code } = req.body;
  if (!process.env.ADMIN_CODE || code !== process.env.ADMIN_CODE) {
    return res.status(403).json({ error: 'wrong_code' });
  }
  await updateUser(user.id, { isAdmin: true });
  res.json({ user: publicUser({ ...user, isAdmin: true }) });
});
app.post('/api/auth/admin/deactivate', async (req, res) => {
  const user = await findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  await updateUser(user.id, { isAdmin: false });
  res.json({ user: publicUser({ ...user, isAdmin: false }) });
});

app.post('/api/auth/plan', async (req, res) => {
  const user = await findUserById(req.session.userId);
  if (!user) return res.status(401).json({ error: 'not_authenticated' });
  const { plan } = req.body;
  if (!['free', 'plus', 'premium'].includes(plan)) {
    return res.status(400).json({ error: 'invalid_plan' });
  }
  await updateUser(user.id, { plan });
  res.json({ user: publicUser({ ...user, plan }) });
});

async function getAllFeedback() {
  const { data, error } = await supabase.from('feedback').select('*').order('date', { ascending: false });
  if (error) throw error;
  return data || [];
}
async function insertFeedback(entry) {
  const { error } = await supabase.from('feedback').insert(entry);
  if (error) throw error;
}

app.post('/api/feedback', async (req, res) => {
  const { name, rating, message, lang } = req.body;
  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'message_required' });
  }
  try {
    await insertFeedback({
      id: Date.now(),
      name: (name || '').trim() || (lang === 'pt' ? 'Anônimo' : 'Anonymous'),
      rating: Number(rating) || 0,
      message: message.trim(),
      date: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('feedback error:', err.message);
    res.status(500).json({ error: 'feedback_failed' });
  }
});

// visite http://localhost:3000/api/feedback no navegador pra ver tudo que foi enviado
app.get('/api/feedback', async (req, res) => {
  try {
    res.json(await getAllFeedback());
  } catch (err) {
    console.error('feedback list error:', err.message);
    res.status(500).json({ error: 'feedback_list_failed' });
  }
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
    if (req.session.userId) await addStudyMinutes(req.session.userId, 1);
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
function rowToMaterial(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    title: row.title,
    type: row.type,
    goal: row.goal,
    date: row.date,
    sourceText: row.source_text,
    resumo: row.resumo || [],
    flashcards: row.flashcards || [],
    mindmap: row.mindmap || [],
    explanation: row.explanation
  };
}
function materialToRow(m) {
  return {
    id: m.id,
    user_id: m.userId,
    title: m.title,
    type: m.type,
    goal: m.goal,
    date: m.date,
    source_text: m.sourceText,
    resumo: m.resumo || [],
    flashcards: m.flashcards || [],
    mindmap: m.mindmap || [],
    explanation: m.explanation || null
  };
}
async function getMaterialsByUser(userId) {
  const { data, error } = await supabase.from('materials').select('*').eq('user_id', userId).order('id', { ascending: false });
  if (error) throw error;
  return (data || []).map(rowToMaterial);
}
async function getMaterialById(id) {
  const { data, error } = await supabase.from('materials').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return rowToMaterial(data);
}
async function insertMaterial(material) {
  const { data, error } = await supabase.from('materials').insert(materialToRow(material)).select().single();
  if (error) throw error;
  return rowToMaterial(data);
}
async function updateMaterialExplanation(id, explanation) {
  const { error } = await supabase.from('materials').update({ explanation }).eq('id', id);
  if (error) throw error;
}

// ---------- simulado (objetivo) e prova (descritiva) gerados a partir de um material ----------
function rowToQuiz(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    materialId: row.material_id,
    materialTitle: row.material_title,
    mode: row.mode,
    difficulty: row.difficulty,
    count: row.count,
    questions: row.questions || [],
    answers: row.answers,
    results: row.results,
    status: row.status,
    date: row.date
  };
}
function quizToRow(q) {
  return {
    id: q.id,
    user_id: q.userId,
    material_id: q.materialId,
    material_title: q.materialTitle,
    mode: q.mode,
    difficulty: q.difficulty,
    count: q.count,
    questions: q.questions || [],
    answers: q.answers || null,
    results: q.results || null,
    status: q.status,
    date: q.date
  };
}
async function getQuizById(id) {
  const { data, error } = await supabase.from('quizzes').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return rowToQuiz(data);
}
async function insertQuiz(quiz) {
  const { data, error } = await supabase.from('quizzes').insert(quizToRow(quiz)).select().single();
  if (error) throw error;
  return rowToQuiz(data);
}
async function updateQuizResults(id, { answers, results, status }) {
  const { error } = await supabase.from('quizzes').update({ answers, results, status }).eq('id', id);
  if (error) throw error;
}

function isPlanLocked(user) {
  return !user.isAdmin && user.plan === 'free';
}

const QUIZ_COUNTS = [10, 20, 30, 40, 50];
const QUIZ_DIFFICULTIES = ['facil', 'medio', 'dificil'];
const DIFFICULTY_LABEL = {
  pt: { facil: 'fácil', medio: 'médio', dificil: 'difícil' },
  en: { facil: 'easy', medio: 'medium', dificil: 'hard' }
};

async function requireAuth(req, res) {
  const user = await findUserById(req.session.userId);
  if (!user) {
    res.status(401).json({ error: 'not_authenticated' });
    return null;
  }
  return user;
}

app.get('/api/materials', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    res.json({ materials: await getMaterialsByUser(user.id) });
  } catch (err) {
    console.error('materials list error:', err.message);
    res.status(500).json({ error: 'materials_list_failed' });
  }
});

app.post('/api/materials', async (req, res) => {
  const user = await requireAuth(req, res);
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

    const material = await insertMaterial({
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
    });
    await addStudyMinutes(user.id, 5);

    res.json({ material });
  } catch (err) {
    console.error('materials error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/materials/:id/explain', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { lang = 'pt' } = req.body;
  const material = await getMaterialById(Number(req.params.id));
  if (!material || material.userId !== user.id) return res.status(404).json({ error: 'not_found' });

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
    await updateMaterialExplanation(material.id, text);
    await addStudyMinutes(user.id, 8);
    res.json({ explanation: text });
  } catch (err) {
    console.error('material explain error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/simulado', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (isPlanLocked(user)) return res.status(403).json({ error: 'plan_locked' });

  const { materialId, count, difficulty, lang = 'pt' } = req.body;
  if (!QUIZ_COUNTS.includes(Number(count)) || !QUIZ_DIFFICULTIES.includes(difficulty)) {
    return res.status(400).json({ error: 'invalid_params' });
  }
  const material = await getMaterialById(Number(materialId));
  if (!material || material.userId !== user.id) return res.status(404).json({ error: 'material_not_found' });

  const diffLabel = DIFFICULTY_LABEL[lang === 'en' ? 'en' : 'pt'][difficulty];
  const systemInstruction = lang === 'pt'
    ? `Você é o Studycast AI. A partir do texto de material de estudo fornecido, gere exatamente ${count} questões de múltipla escolha com nível de dificuldade ${diffLabel}, cada uma com 4 alternativas e apenas 1 correta. Responda APENAS com um JSON válido, sem texto antes ou depois, sem markdown e sem crases, exatamente neste formato: [{"q":"enunciado da questão","options":["alternativa A","alternativa B","alternativa C","alternativa D"],"correct":0}]. O campo "correct" é o índice (0 a 3) da alternativa certa. Varie a posição da alternativa correta entre as questões.`
    : `You are Studycast AI. From the given study material text, generate exactly ${count} multiple-choice questions at ${diffLabel} difficulty, each with 4 options and only 1 correct answer. Respond ONLY with valid JSON, no text before or after, no markdown, no backticks, in exactly this format: [{"q":"question text","options":["option A","option B","option C","option D"],"correct":0}]. The "correct" field is the index (0 to 3) of the right option. Vary the position of the correct option across questions.`;

  const userPrompt = lang === 'pt'
    ? `Material: "${material.title}"\n\nTexto do material:\n${(material.sourceText || material.title).slice(0, 6000)}\n\nGere as ${count} questões de múltipla escolha.`
    : `Material: "${material.title}"\n\nMaterial text:\n${(material.sourceText || material.title).slice(0, 6000)}\n\nGenerate the ${count} multiple-choice questions.`;

  try {
    const { text } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'simulado');
    const questions = extractJsonArray(text)
      .filter(q => q && q.q && Array.isArray(q.options) && q.options.length === 4 && Number.isInteger(q.correct))
      .map(q => ({ q: q.q, options: q.options, correct: Math.min(3, Math.max(0, q.correct)) }));
    if (!questions.length) throw new Error('no_valid_questions');

    const quiz = await insertQuiz({
      id: Date.now(),
      userId: user.id,
      materialId: material.id,
      materialTitle: material.title,
      mode: 'simulado',
      difficulty,
      count: questions.length,
      questions,
      results: null,
      status: 'pending',
      date: new Date().toISOString()
    });

    res.json({ quiz: { id: quiz.id, materialTitle: quiz.materialTitle, mode: quiz.mode, difficulty, questions: questions.map(({ q, options }) => ({ q, options })) } });
  } catch (err) {
    console.error('simulado error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/simulado/:id/submit', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const quiz = await getQuizById(Number(req.params.id));
  if (!quiz || quiz.userId !== user.id || quiz.mode !== 'simulado') return res.status(404).json({ error: 'not_found' });

  if (quiz.status === 'submitted') {
    return res.json({ results: quiz.results });
  }

  const { answers } = req.body;
  if (!Array.isArray(answers) || answers.length !== quiz.questions.length) {
    return res.status(400).json({ error: 'invalid_answers' });
  }

  const perQuestion = quiz.questions.map((question, i) => ({
    correctIndex: question.correct,
    yourIndex: answers[i],
    isCorrect: Number(answers[i]) === question.correct
  }));
  const correctCount = perQuestion.filter(p => p.isCorrect).length;
  const results = {
    total: quiz.questions.length,
    correctCount,
    score: (correctCount / quiz.questions.length) * 100,
    perQuestion
  };

  await updateQuizResults(quiz.id, { answers, results, status: 'submitted' });
  await addStudyMinutes(user.id, Math.round(quiz.questions.length * 0.5));

  res.json({ results });
});

app.post('/api/prova', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (isPlanLocked(user)) return res.status(403).json({ error: 'plan_locked' });

  const { materialId, count, difficulty, lang = 'pt' } = req.body;
  if (!QUIZ_COUNTS.includes(Number(count)) || !QUIZ_DIFFICULTIES.includes(difficulty)) {
    return res.status(400).json({ error: 'invalid_params' });
  }
  const material = await getMaterialById(Number(materialId));
  if (!material || material.userId !== user.id) return res.status(404).json({ error: 'material_not_found' });

  const diffLabel = DIFFICULTY_LABEL[lang === 'en' ? 'en' : 'pt'][difficulty];
  const systemInstruction = lang === 'pt'
    ? `Você é o Studycast AI. A partir do texto de material de estudo fornecido, gere exatamente ${count} questões descritivas (dissertativas, sem alternativas) com nível de dificuldade ${diffLabel}, que exijam uma resposta escrita explicando ou desenvolvendo um conceito do material. Responda APENAS com um JSON válido, sem texto antes ou depois, sem markdown e sem crases, exatamente neste formato: [{"q":"enunciado da questão descritiva"}].`
    : `You are Studycast AI. From the given study material text, generate exactly ${count} open-ended (essay-style) questions at ${diffLabel} difficulty, requiring a written answer explaining or developing a concept from the material. Respond ONLY with valid JSON, no text before or after, no markdown, no backticks, in exactly this format: [{"q":"open-ended question text"}].`;

  const userPrompt = lang === 'pt'
    ? `Material: "${material.title}"\n\nTexto do material:\n${(material.sourceText || material.title).slice(0, 6000)}\n\nGere as ${count} questões descritivas.`
    : `Material: "${material.title}"\n\nMaterial text:\n${(material.sourceText || material.title).slice(0, 6000)}\n\nGenerate the ${count} open-ended questions.`;

  try {
    const { text } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'prova');
    const questions = extractJsonArray(text)
      .filter(q => q && q.q)
      .map(q => ({ q: q.q }));
    if (!questions.length) throw new Error('no_valid_questions');

    const quiz = await insertQuiz({
      id: Date.now(),
      userId: user.id,
      materialId: material.id,
      materialTitle: material.title,
      mode: 'prova',
      difficulty,
      count: questions.length,
      questions,
      results: null,
      status: 'pending',
      date: new Date().toISOString()
    });

    res.json({ quiz: { id: quiz.id, materialTitle: quiz.materialTitle, mode: quiz.mode, difficulty, questions } });
  } catch (err) {
    console.error('prova error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/prova/:id/submit', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;

  const quiz = await getQuizById(Number(req.params.id));
  if (!quiz || quiz.userId !== user.id || quiz.mode !== 'prova') return res.status(404).json({ error: 'not_found' });

  if (quiz.status === 'submitted') {
    return res.json({ results: quiz.results });
  }

  const { answers, lang = 'pt' } = req.body;
  if (!Array.isArray(answers) || answers.length !== quiz.questions.length) {
    return res.status(400).json({ error: 'invalid_answers' });
  }

  const material = await getMaterialById(quiz.materialId);
  const qaBlock = quiz.questions.map((q, i) => (lang === 'pt'
    ? `Questão ${i + 1}: ${q.q}\nResposta do aluno: ${answers[i]}`
    : `Question ${i + 1}: ${q.q}\nStudent's answer: ${answers[i]}`)).join('\n\n');

  const systemInstruction = lang === 'pt'
    ? 'Você é o Studycast AI, corrigindo uma prova descritiva. Para cada questão, avalie a resposta do aluno com base no material de referência e dê uma nota de 0 a 10 e um feedback curto e construtivo (o que acertou, o que faltou ou errou). Também dê uma nota geral de 0 a 10 (pode ter casas decimais) e um feedback geral breve. Responda APENAS com um JSON válido, sem texto antes ou depois, sem markdown e sem crases, exatamente neste formato: {"perQuestion":[{"score":7,"feedback":"comentário curto"}],"overallScore":7.5,"overallFeedback":"comentário geral curto"}. A lista perQuestion deve ter exatamente uma entrada por questão, na mesma ordem.'
    : 'You are Studycast AI, grading an open-ended exam. For each question, evaluate the student\'s answer against the reference material and give a score from 0 to 10 and short, constructive feedback (what was right, what was missing or wrong). Also give an overall score from 0 to 10 (decimals allowed) and a brief overall feedback. Respond ONLY with valid JSON, no text before or after, no markdown, no backticks, in exactly this format: {"perQuestion":[{"score":7,"feedback":"short comment"}],"overallScore":7.5,"overallFeedback":"short overall comment"}. The perQuestion list must have exactly one entry per question, in the same order.';

  const userPrompt = lang === 'pt'
    ? `Material de referência: "${quiz.materialTitle}"\n${material ? `Texto do material:\n${(material.sourceText || '').slice(0, 4000)}\n\n` : ''}${qaBlock}\n\nCorrija cada resposta e dê a nota geral.`
    : `Reference material: "${quiz.materialTitle}"\n${material ? `Material text:\n${(material.sourceText || '').slice(0, 4000)}\n\n` : ''}${qaBlock}\n\nGrade each answer and give the overall score.`;

  try {
    const { text } = await withFallback([
      { name: 'gemini', run: () => callGemini(systemInstruction, [{ role: 'user', parts: [{ text: userPrompt }] }]) },
      { name: 'groq', run: () => callGroq(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'openrouter', run: () => callOpenRouter(systemInstruction, [{ role: 'user', content: userPrompt }]) },
      { name: 'cloudflare', run: () => callCloudflare(systemInstruction, [{ role: 'user', content: userPrompt }]) }
    ], 'correção de prova');
    const graded = extractJsonObject(text);
    const perQuestion = quiz.questions.map((_, i) => {
      const g = (graded.perQuestion && graded.perQuestion[i]) || {};
      return { score: Number.isFinite(g.score) ? g.score : 0, feedback: g.feedback || '' };
    });
    const results = {
      perQuestion,
      overallScore: Number.isFinite(graded.overallScore) ? graded.overallScore : 0,
      overallFeedback: graded.overallFeedback || ''
    };

    await updateQuizResults(quiz.id, { answers, results, status: 'submitted' });
    await addStudyMinutes(user.id, Math.round(quiz.questions.length * 1.5));

    res.json({ results });
  } catch (err) {
    console.error('prova submit error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/stats', async (req, res) => {
  const user = await requireAuth(req, res);
  if (!user) return;
  try {
    const mine = await getMaterialsByUser(user.id);
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
  } catch (err) {
    console.error('stats error:', err.message);
    res.status(500).json({ error: 'stats_failed' });
  }
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
// rate limit) segue o briefing tecnico do audio. Fica em arquivo local de proposito: e so
// cache/contador, perder isso no pior caso regenera audio, nao perde trabalho de ninguem.
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

// rate limit por usuario (em memoria — reseta se o servidor reiniciar, o que aqui e aceitavel)
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

app.get('/api/tts/usage', async (req, res) => {
  const user = await requireAuth(req, res);
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
  const user = await requireAuth(req, res);
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
    await addStudyMinutes(user.id, minutes);

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
