const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';

// =============================================
// CONFIGURAÇÃO DO JSONBIN
// Substitua os valores abaixo pelas suas chaves
// =============================================
const JSONBIN_API_KEY = process.env.JSONBIN_API_KEY || 'COLE_SUA_API_KEY_AQUI';
const JSONBIN_BIN_ID  = process.env.JSONBIN_BIN_ID  || 'COLE_SEU_BIN_ID_AQUI';
const JSONBIN_URL     = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`;

// Credenciais do admin (inalteradas)
const USUARIO    = 'Lelinstore';
const SENHA_HASH = '$2b$12$q5WNFlw2bCjhnX8.Ft6hV.UtxuPvlizN1r8RC3q6TBeg9tr9LBll2';

// =============================================
// FUNÇÕES DE ACESSO AO JSONBIN
// =============================================
async function buscarProdutos() {
  const res = await fetch(`${JSONBIN_URL}/latest`, {
    headers: {
      'X-Master-Key': JSONBIN_API_KEY,
      'X-Bin-Meta':   'false'
    }
  });
  if (!res.ok) throw new Error('Erro ao buscar no JSONBin');
  return await res.json(); // retorna o array de produtos
}

async function salvarProdutos(produtos) {
  const res = await fetch(JSONBIN_URL, {
    method:  'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-Master-Key': JSONBIN_API_KEY
    },
    body: JSON.stringify(produtos)
  });
  if (!res.ok) throw new Error('Erro ao salvar no JSONBin');
  return await res.json();
}

// =============================================
// CONTROLE DE TENTATIVAS DE LOGIN
// =============================================
const tentativas = {};

function verificarBloqueio(ip) {
  const t = tentativas[ip];
  if (!t) return false;
  if (t.bloqueadoAte && Date.now() < t.bloqueadoAte) return true;
  return false;
}

function registrarFalha(ip) {
  if (!tentativas[ip]) tentativas[ip] = { count: 0, bloqueadoAte: null };
  tentativas[ip].count++;
  if (tentativas[ip].count >= 5) {
    tentativas[ip].bloqueadoAte = Date.now() + 60 * 1000;
    tentativas[ip].count = 0;
  }
}

function limparTentativas(ip) {
  delete tentativas[ip];
}

// =============================================
// ROTAS
// =============================================

// Login
app.post('/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (verificarBloqueio(ip))
    return res.status(429).json({ success: false, erro: 'Muitas tentativas. Aguarde 60 segundos.' });

  const { user, pass } = req.body;
  if (!user || !pass)
    return res.status(400).json({ success: false, erro: 'Dados inválidos.' });

  const senhaCorreta = await bcrypt.compare(pass, SENHA_HASH);
  if (user === USUARIO && senhaCorreta) {
    limparTentativas(ip);
    const token = jwt.sign({ user: USUARIO, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
    return res.json({ success: true, token });
  }

  registrarFalha(ip);
  return res.status(401).json({ success: false, erro: 'Usuário ou senha incorretos.' });
});

// Buscar produtos
app.get('/produtos', async (req, res) => {
  try {
    const produtos = await buscarProdutos();
    res.json(produtos);
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao buscar produtos.' });
  }
});

// Salvar produtos (requer token)
app.post('/produtos', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer '))
    return res.status(401).json({ erro: 'Não autorizado.' });

  try {
    jwt.verify(auth.slice(7), JWT_SECRET);
    const produtos = req.body;
    await salvarProdutos(produtos);
    res.json({ success: true });
  } catch {
    res.status(401).json({ erro: 'Token inválido.' });
  }
});

app.listen(3000, () => console.log('Servidor rodando em http://localhost:3000'));
