const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';
const MONGO_URL = process.env.MONGO_URL || 'mongodb+srv://lelioebabi10_db_user:Of9HtAjaJYglv770@cluster0.pn8s2hv.mongodb.net/lelinstore?appName=Cluster0';

const USUARIO = 'Lelinstore';
const SENHA_HASH = '$2b$12$q5WNFlw2bCjhnX8.Ft6hV.UtxuPvlizN1r8RC3q6TBeg9tr9LBll2';

let db;
MongoClient.connect(MONGO_URL).then(client => {
  db = client.db('lelinstore');
  console.log('Conectado ao MongoDB!');
});

// Controle de tentativas
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
function limparTentativas(ip) { delete tentativas[ip]; }

// Login
app.post('/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (verificarBloqueio(ip)) return res.status(429).json({ success: false, erro: 'Muitas tentativas. Aguarde 60 segundos.' });
  const { user, pass } = req.body;
  if (!user || !pass) return res.status(400).json({ success: false, erro: 'Dados inválidos.' });
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
    const produtos = await db.collection('produtos').find().toArray();
    res.json(produtos);
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao buscar produtos.' });
  }
});

// Salvar produtos
app.post('/produtos', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ erro: 'Não autorizado.' });
  try {
    jwt.verify(auth.slice(7), JWT_SECRET);
    const produtos = req.body;
    await db.collection('produtos').deleteMany({});
    if (produtos.length > 0) await db.collection('produtos').insertMany(produtos);
    res.json({ success: true });
  } catch {
    res.status(401).json({ erro: 'Token inválido.' });
  }
});

app.listen(3000, () => console.log('Servidor rodando em http://localhost:3000'));
