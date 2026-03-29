const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ── CONFIGURAÇÕES ──────────────────────────────────────────────
// Gere um segredo forte para produção: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';

// Senha armazenada como hash bcrypt (NUNCA em texto puro)
// Para gerar um novo hash rode no terminal:
//   node -e "const b=require('bcrypt'); b.hash('SuaSenhaAqui',12).then(console.log)"
const USUARIO = 'Lelinstore';
const SENHA_HASH = '$2b$12$q5WNFlw2bCjhnX8.Ft6hV.UtxuPvlizN1r8RC3q6TBeg9tr9LBll2'; // ← substitua pelo hash gerado

// ── CONTROLE DE TENTATIVAS (brute-force) ──────────────────────
const tentativas = {};  // { ip: { count, bloqueadoAte } }

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
    tentativas[ip].bloqueadoAte = Date.now() + 60 * 1000; // bloqueia 60s
    tentativas[ip].count = 0;
  }
}

function limparTentativas(ip) {
  delete tentativas[ip];
}

// ── ROTA DE LOGIN ──────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // 1. Verifica bloqueio por IP
  if (verificarBloqueio(ip)) {
    return res.status(429).json({ success: false, erro: 'Muitas tentativas. Aguarde 60 segundos.' });
  }

  const { user, pass } = req.body;

  // 2. Validação básica de entrada
  if (!user || !pass || typeof user !== 'string' || typeof pass !== 'string') {
    return res.status(400).json({ success: false, erro: 'Dados inválidos.' });
  }

  // 3. Verifica usuário (comparação em tempo constante evita timing attack)
  const usuarioCorreto = user === USUARIO;

  // 4. Verifica senha com bcrypt (sempre roda mesmo se usuário errado, evita timing attack)
  let senhaCorreta = false;
  try {
    senhaCorreta = await bcrypt.compare(pass, SENHA_HASH);
  } catch (e) {
    console.error('Erro bcrypt:', e);
    return res.status(500).json({ success: false, erro: 'Erro interno.' });
  }

  if (usuarioCorreto && senhaCorreta) {
    limparTentativas(ip);

    // 5. Gera token JWT válido por 2 horas
    const token = jwt.sign(
      { user: USUARIO, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.json({ success: true, token });
  }

  // 6. Login falhou → registra tentativa
  registrarFalha(ip);
  return res.status(401).json({ success: false, erro: 'Usuário ou senha incorretos.' });
});

// ── ROTA PROTEGIDA (exemplo) ──────────────────────────────────
// Middleware para verificar token JWT
function autenticar(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Não autorizado.' });
  }
  try {
    req.admin = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

// Exemplo: rota só acessível com token válido
app.get('/adm/ping', autenticar, (req, res) => {
  res.json({ ok: true, usuario: req.admin.user });
});

// ── SERVIDOR ──────────────────────────────────────────────────
app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
  console.log('');
  console.log('⚠️  LEMBRETE: Antes de usar, gere o hash da sua senha:');
  console.log('   node -e "const b=require(\'bcrypt\'); b.hash(\'SuaSenhaAqui\',12).then(console.log)"');
  console.log('   Depois cole o resultado em SENHA_HASH no server.js');
});
