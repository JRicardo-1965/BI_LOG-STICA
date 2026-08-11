// Backend do BI de Ressuprimento (Aqui Tem Mais) — login + filtro por empresa.
//
// Como funciona, em resumo:
// 1. O extract_bi.ps1 (rodando no PC do Ricardo, único lugar com acesso ao Access) gera os dados
//    e envia num POST /api/sync protegido por um segredo compartilhado (SYNC_SECRET). Nada mais
//    além desse endpoint consegue gravar dados aqui.
// 2. Login (POST /api/login) confere e-mail+senha contra o snapshot mais recente sincronizado
//    (senha comparada com bcrypt — a senha em texto puro nunca é gravada em disco aqui, só o hash).
// 3. Cada requisição autenticada em GET / relê, na hora, quais empresas aquele e-mail tem vinculadas
//    em USUARIOS_EMPRESAS (sempre o snapshot mais recente, não fica "preso" no que valia no login) —
//    e manda pro navegador só os dados dessas empresas, filtrados aqui no servidor. O HTML que sai
//    daqui nunca contém dado de empresa que o usuário não pode ver.
const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SYNC_SECRET = process.env.SYNC_SECRET;
const IS_PROD = process.env.NODE_ENV === 'production';

if (!SESSION_SECRET || !SYNC_SECRET) {
  console.error('ERRO: defina as variáveis de ambiente SESSION_SECRET e SYNC_SECRET antes de iniciar.');
  process.exit(1);
}

const DATA_FILE = path.join(__dirname, 'data', 'data.json');
const TEMPLATE_PATH = path.join(__dirname, 'templates', 'dashboard_template.html');
const LOGO_PATH = path.join(__dirname, 'logo_b64.txt');

const TEMPLATE = fs.readFileSync(TEMPLATE_PATH, 'utf8').replace(/^﻿/, '');
const LOGO_B64 = fs.existsSync(LOGO_PATH) ? fs.readFileSync(LOGO_PATH, 'utf8').replace(/^﻿/, '').trim() : '';

let latestData = null;
if (fs.existsSync(DATA_FILE)) {
  try {
    latestData = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    console.log(`Dados carregados do disco (sincronizados em ${latestData.syncedAt}).`);
  } catch (err) {
    console.error('Não consegui ler data/data.json existente, começando vazio:', err.message);
  }
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // o dashboard tem <style>/<script> inline, então desliga só o CSP do helmet
app.use(cookieParser());

// --- helpers ---------------------------------------------------------------

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// Evita que dado vindo do Access feche a tag <script> se por acaso tiver "</script>" dentro de um
// texto (nome de cliente/produto, etc.) — defesa extra além do escapeHtml usado nos textos soltos.
function jsonForScript(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function filterByEmpresas(arr, allowed) {
  if (!Array.isArray(arr)) return [];
  return arr.filter((row) => allowed.includes(String(row.CodEmpresa)));
}

function empresasDoUsuario(email) {
  if (!latestData) return [];
  const alvo = String(email).toLowerCase();
  return latestData.usuariosEmpresas
    .filter((v) => String(v.email).toLowerCase() === alvo)
    .map((v) => String(v.empresa));
}

function usuarioAtivo(email) {
  if (!latestData) return null;
  const alvo = String(email).toLowerCase();
  return latestData.usuarios.find((u) => String(u.email).toLowerCase() === alvo && u.ativo) || null;
}

// --- autenticação ------------------------------------------------------------

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.session;
  if (!token) return res.redirect('/login');
  let payload;
  try {
    payload = jwt.verify(token, SESSION_SECRET);
  } catch (err) {
    res.clearCookie('session');
    return res.redirect('/login');
  }
  // revalida a cada requisição contra o snapshot mais recente — se o usuário foi desativado ou
  // removido depois do login, o acesso cai na hora, sem precisar esperar o token expirar.
  const usuario = usuarioAtivo(payload.email);
  if (!usuario) {
    res.clearCookie('session');
    return res.redirect('/login?desativado=1');
  }
  req.userEmail = payload.email;
  req.userNome = usuario.nome || payload.email;
  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Muitas tentativas de login. Tente de novo em alguns minutos.' }
});

app.post('/api/login', express.json(), loginLimiter, async (req, res) => {
  const email = String((req.body && req.body.email) || '').trim();
  const senha = String((req.body && req.body.senha) || '');
  if (!email || !senha) return res.status(400).json({ ok: false, error: 'Informe e-mail e senha.' });
  if (!latestData) return res.status(503).json({ ok: false, error: 'Ainda não há dados sincronizados neste servidor.' });

  const usuario = usuarioAtivo(email);
  if (!usuario) return res.status(401).json({ ok: false, error: 'E-mail ou senha incorretos.' });

  const ok = await bcrypt.compare(senha, usuario.passwordHash);
  if (!ok) return res.status(401).json({ ok: false, error: 'E-mail ou senha incorretos.' });

  const token = jwt.sign({ email: usuario.email }, SESSION_SECRET, { expiresIn: '12h' });
  res.cookie('session', token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 12 * 60 * 60 * 1000
  });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

// --- sincronização (só o extract_bi.ps1 / local_server.js do Ricardo chama isso) -------------

app.post('/api/sync', express.json({ limit: '25mb' }), async (req, res) => {
  const secret = req.header('X-Sync-Secret');
  if (!secret || secret !== SYNC_SECRET) return res.status(403).json({ ok: false, error: 'Segredo de sincronização inválido.' });

  const body = req.body || {};
  try {
    const usuarios = await Promise.all((body.usuarios || []).map(async (u) => ({
      email: u.email,
      nome: u.nome || u.email,
      ativo: !!u.ativo,
      passwordHash: await bcrypt.hash(String(u.senhaPlano || ''), 10)
    })));

    latestData = {
      estoque: body.estoque || [],
      ranking: body.ranking || [],
      clientes: body.clientes || [],
      metas: body.metas || [],
      metaSegmento: body.metaSegmento || [],
      metaProduto: body.metaProduto || [],
      meta: body.meta || {},
      usuarios,
      usuariosEmpresas: (body.usuariosEmpresas || []).map((v) => ({ email: v.email, empresa: String(v.empresa) })),
      syncedAt: new Date().toISOString()
    };

    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(latestData));

    console.log(`Sincronizado às ${latestData.syncedAt} — ${usuarios.length} usuários, ${latestData.clientes.length} clientes.`);
    res.json({ ok: true, syncedAt: latestData.syncedAt, usuarios: usuarios.length, clientes: latestData.clientes.length });
  } catch (err) {
    console.error('Erro processando /api/sync:', err);
    res.status(500).json({ ok: false, error: 'Erro ao processar sincronização.' });
  }
});

// --- páginas -----------------------------------------------------------------

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/', requireAuth, (req, res) => {
  if (!latestData) {
    return res.status(503).send('Ainda não há dados sincronizados neste servidor. Peça para o Ricardo rodar a atualização local.');
  }

  const allowed = empresasDoUsuario(req.userEmail);
  const estoque = filterByEmpresas(latestData.estoque, allowed);
  const ranking = filterByEmpresas(latestData.ranking, allowed);
  const clientes = filterByEmpresas(latestData.clientes, allowed);
  const metas = filterByEmpresas(latestData.metas, allowed);
  const metaSegmento = filterByEmpresas(latestData.metaSegmento, allowed);
  const metaProduto = filterByEmpresas(latestData.metaProduto, allowed);
  const meta = latestData.meta || {};

  const html = TEMPLATE
    .replaceAll('__VERSION__', 'hospedado')
    .replaceAll('__RELEASE__', 'login')
    .replaceAll('__LOGO_DATA_URI__', 'data:image/png;base64,' + LOGO_B64)
    .replaceAll('__DATA_JSON__', jsonForScript(estoque))
    .replaceAll('__RANKING_JSON__', jsonForScript(ranking))
    .replaceAll('__CLIENTES_JSON__', jsonForScript(clientes))
    .replaceAll('__METAS_JSON__', jsonForScript(metas))
    .replaceAll('__META_SEGMENTO_JSON__', jsonForScript(metaSegmento))
    .replaceAll('__META_PRODUTO_JSON__', jsonForScript(metaProduto))
    .replaceAll('__TODAY_ISO__', meta.TodayISO || new Date().toISOString().slice(0, 10))
    .replaceAll('__PERIODO_TEXTO__', meta.PeriodoTexto || '')
    .replaceAll('__FONTE_ATUALIZADA_EM__', meta.FonteAtualizadaEm || 'desconhecido')
    .replaceAll('__PROCESSADO_EM__', meta.ProcessadoEm || 'desconhecido')
    .replaceAll('__DH_VENDAS__', meta.DataHoraVendas || 'sem dados')
    .replaceAll('__DH_TRANSFERENCIAS__', meta.DataHoraTransferencias || 'sem dados')
    .replaceAll('__DH_ENTRADAS__', meta.DataHoraEntradas || 'sem dados')
    .replaceAll('__DH_ESTOQUE__', meta.DataHoraEstoque || 'sem dados')
    .replaceAll('__HOSTED_USER_LABEL__', escapeHtml(req.userNome))
    .replaceAll('__HOSTED_SESSION__', '1');

  res.set('Cache-Control', 'no-store');
  res.send(html);
});

app.get('/health', (req, res) => res.status(200).send('ok'));

app.listen(PORT, () => {
  console.log(`Backend do BI de Ressuprimento rodando na porta ${PORT}`);
});
