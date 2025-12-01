// SECURE WEB PROJECT - VERSÃO COMPLETA (INTEGRADA)
require('dotenv').config();
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const helmet = require('helmet'); // Protege por headers HTTP seguros
const rateLimit = require('express-rate-limit'); // Mitigação de brute-force por IP
const csurf = require('csurf'); // Proteção CSRF
const multer = require('multer'); // Uploads (com validações)
const { v4: uuidv4 } = require('uuid'); // Para nomes de arquivo únicos
const fs = require('fs');
const bcrypt = require('bcrypt'); // Hash de senhas
const { Pool } = require('pg');

// TRABALHO EXTRA --- [NOVO] MÓDULOS PARA O  ---
const https = require('https');   // Permite criar o servidor com TLS
const http = require('http');     // Necessário para o redirecionamento
const crypto = require('crypto'); // Biblioteca nativa para Criptografia    

// ------------------------------------------------------------------
// CONFIGURAÇÕES
// ------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3000;      // Porta HTTPS
const HTTP_PORT = process.env.HTTP_PORT || 3001; // Porta HTTP (Redirect)
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const novosUsuariosRoot = "D:\\secure-web-project\\novos usuários"; // local para criar sandbox se user SO não existir
const SALT_ROUNDS = 12; // Ajuste entre 10-15 conforme custo/tempo aceitável

// --- TRABALHO EXTRA -- [NOVO] CONFIGURAÇÃO DE CRIPTOGRAFIA - 
const ENCRYPTION_ALGORITHM = 'aes-256-cbc';
// Garante que a chave existe, senão usa uma padrão apenas para não quebrar o código na apresentação
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY || '12345678901234567890123456789012', 'utf-8');
const IV_LENGTH = 16; 

// DATABASE CONNECTION
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// ------------------------------------------------------------------
//TRABALHO EXTRA --- [NOVO] FUNÇÕES DE CRIPTOGRAFIA (ADICIONADAS AO PROJETO)
// ------------------   ------------------------------------------------

// Função para criptografar arquivo em disco (Substitui o arquivo original pelo cifrado)
async function encryptFile(filePath) {
    try {
        const fileContent = fs.readFileSync(filePath);
        // 1. Gera um IV aleatório para CADA arquivo
        const iv = crypto.randomBytes(IV_LENGTH);
        //2. Cria o cifrador com a chave mestra e o IV
        const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);
        
        // 3. Cifra o conteúdo
        let encrypted = cipher.update(fileContent);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        // Salva: [IV 16 bytes] + [Conteúdo Cifrado]
        const finalBuffer = Buffer.concat([iv, encrypted]);
        // 4. Salva no disco: O IV fica "colado" no começo do arquivo
        fs.writeFileSync(filePath, Buffer.concat([iv, encrypted]));
    } catch (e) {
        console.error("Erro Crítico na Criptografia:", e);
        throw e; // Relança o erro para o upload falhar
    }
}
// TRABALHO EXTRA 
// Função para criar um fluxo de leitura descriptografado (para Download)
function getDecryptedFileStream(filePath) {
    // 1. Abre o arquivo e lê apenas os primeiros 16 bytes (o IV)
    const fd = fs.openSync(filePath, 'r');
    const iv = Buffer.alloc(IV_LENGTH);
    fs.readSync(fd, iv, 0, IV_LENGTH, 0);
    fs.closeSync(fd);

    // 2. Configura o decifrador usando a chave e o IV que lemos
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);

    // 3. Cria um fluxo de leitura pulando o cabeçalho
    const readStream = fs.createReadStream(filePath, { start: IV_LENGTH });
    
    // 4. Entrega o arquivo limpo
    return readStream.pipe(decipher);
}

// ------------------------------------------------------------------
// Utility functions (segurança/neutralização) - MANTIDAS ORIGINAIS
// ------------------------------------------------------------------

function sanitizeForLog(s) {
    if (s == null) return s;
    return String(s).replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
}

function sanitizeForDisplay(s) {
    if (s == null) return '';
    return String(s)
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

function safeJoin(base, filename) {
    const resolvedBase = path.resolve(base);
    const resolvedPath = path.resolve(path.join(resolvedBase, filename));
    if (!resolvedPath.startsWith(resolvedBase)) throw new Error('Invalid path');
    return resolvedPath;
}

function mkdirSecureSync(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
    } else {
        try { fs.chmodSync(dirPath, 0o700); } catch (e) { /* ignora */ }
    }
}

// ------------------------------------------------------------------
// Funções para validação de caminhos físicos (MANTIDAS ORIGINAIS)
// ------------------------------------------------------------------

function getWindowsUserHomeIfExists(username) {
    const systemDrive = process.env.SystemDrive || 'C:';
    const candidate = path.join(systemDrive + path.sep, 'Users', username);
    if (fs.existsSync(candidate)) return path.resolve(candidate);
    return null;
}

function hasSymlinkInPathSync(targetPath, stopAt) {
    const parsed = path.parse(targetPath);
    let cur = parsed.root;
    const parts = targetPath.slice(parsed.root.length).split(path.sep).filter(Boolean);
    for (const part of parts) {
        cur = path.join(cur, part);
        try {
            const st = fs.lstatSync(cur);
            if (st.isSymbolicLink()) return true;
        } catch (e) { }
        if (stopAt) {
            try { if (fs.realpathSync(cur) === stopAt) break; } catch (e) { }
        }
    }
    return false;
}

function isPathInside(allowedRoot, resolvedPath) {
    const realAllowed = path.resolve(allowedRoot);
    const realResolved = path.resolve(resolvedPath);
    const prefix = realAllowed.endsWith(path.sep) ? realAllowed : realAllowed + path.sep;
    return realResolved === realAllowed || realResolved.startsWith(prefix);
}

function validateClientPhysicalPath(webUsername, clientPath) {
    if (typeof clientPath !== 'string' || clientPath.trim() === '') {
        throw new Error('Caminho inválido');
    }
    let allowedRoot = getWindowsUserHomeIfExists(webUsername);
    if (!allowedRoot) {
        mkdirSecureSync(novosUsuariosRoot);
        allowedRoot = path.join(novosUsuariosRoot, webUsername);
        mkdirSecureSync(allowedRoot);
    }
    let candidate = path.isAbsolute(clientPath)
        ? path.normalize(clientPath)
        : path.join(allowedRoot, clientPath);
    let realCandidate;
    try { realCandidate = fs.realpathSync(candidate); } catch (e) { realCandidate = path.resolve(candidate); }
    let realAllowed;
    try { realAllowed = fs.realpathSync(allowedRoot); } catch (e) { realAllowed = path.resolve(allowedRoot); }

    if (hasSymlinkInPathSync(realCandidate, realAllowed)) {
        throw new Error('Caminho inválido: presença de link simbólico detectada');
    }
    if (!isPathInside(realAllowed, realCandidate)) {
        throw new Error('Acesso negado: caminho fora da raiz do usuário');
    }
    return realCandidate;
}

async function audit(userId, eventType, metadata, ip) {
    try {
        const safeMeta = metadata ? JSON.stringify(metadata) : null;
        await pool.query(
            'INSERT INTO audit_logs (user_id, event_type, event_metadata, ip_addr) VALUES ($1,$2,$3,$4)',
            [userId || null, eventType, safeMeta, ip || null]
        );
    } catch (e) { console.error('Audit log error:', e.message); }
}

// ------------------------------------------------------------------
// AUTH FUNCTIONS (MANTIDAS)
// ------------------------------------------------------------------
async function registerUser({ username, password }) {
    const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rowCount > 0) {
        const error = new Error('Usuário já existe');
        error.code = 'USER_EXISTS';
        throw error;
    }
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
        'INSERT INTO users (username, password_hash) VALUES ($1,$2) RETURNING id',
        [username, hash]
    );
    const userId = result.rows[0].id;
    const existingHome = getWindowsUserHomeIfExists(username);
    if (!existingHome) {
        const userSandbox = path.join(novosUsuariosRoot, username);
        mkdirSecureSync(novosUsuariosRoot);
        mkdirSecureSync(userSandbox);
    }
    return userId;
}

async function findUserByUsername(username) {
    const r = await pool.query(
        'SELECT id, username, password_hash, locked_until FROM users WHERE username = $1',
        [username]
    );
    return r.rows[0];
}

// ------------------------------------------------------------------
// MIDDLEWARES
// ------------------------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(helmet()); 
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use((req, res, next) => {
    res.charset = 'utf-8';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    next();
});

app.use(session({
    store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || 'dev_secret_change_this',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true, // [ALTERADO] True para HTTPS (Requisito TLS)
        sameSite: 'lax',
    }
}));

const csrfProtection = csurf();
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Muitas tentativas.' });

if (!fs.existsSync(uploadDir)) mkdirSecureSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const webUsername = req.session?.username;
        if (!webUsername) return cb(new Error('Usuário não autenticado'));
        let base = getWindowsUserHomeIfExists(webUsername);
        if (!base) {
            mkdirSecureSync(novosUsuariosRoot);
            base = path.join(novosUsuariosRoot, webUsername);
            mkdirSecureSync(base);
        }
        const uploadPath = path.join(base, 'uploads');
        mkdirSecureSync(uploadPath);
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const ext = path.extname(originalName);
        cb(null, uuidv4() + ext);
    },
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, 
    fileFilter: (req, file, cb) => {
        file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
        cb(null, true);
    }
});

function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
}

// ------------------------------------------------------------------
// ROUTES (COM INTEGRAÇÃO DE CRIPTOGRAFIA)
// ------------------------------------------------------------------

app.get('/', (req, res) => res.redirect('/login'));

app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { csrfToken: req.csrfToken(), error: null });
});

app.post('/register', csrfProtection, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Campos obrigatórios' });
    if (username.length < 3) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Min 3 chars' });
    if (password.length < 6) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Min 6 chars' });

    try {
        const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
        if (existing.rowCount > 0) return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Usuário já existe' });
        
        const userId = await registerUser({ username, password });
        await audit(userId, 'user_registered', { username: sanitizeForLog(username) }, req.ip);
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.status(500).render('register', { csrfToken: req.csrfToken(), error: 'Erro no registro' });
    }
});

app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { csrfToken: req.csrfToken(), error: null });
});

app.post('/login', loginLimiter, csrfProtection, async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await findUserByUsername(username);
        if (!user) {
            await audit(null, 'login_failed', { username: sanitizeForLog(username) }, req.ip);
            return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Credenciais inválidas' });
        }
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            await audit(user.id, 'login_failed', { username: sanitizeForLog(username) }, req.ip);
            return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Credenciais inválidas' });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        await audit(user.id, 'login_success', { username: sanitizeForLog(user.username) }, req.ip);
        writeLog(req.session.username, 'login_success', { ip: req.ip });
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.status(500).render('login', { csrfToken: req.csrfToken(), error: 'Erro no login.' });
    }
});

app.get('/dashboard', requireAuth, csrfProtection, async (req, res) => {
    try {
        const logsResult = await pool.query('SELECT id, event_type, event_metadata, ip_addr, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [req.session.userId]);
        const filesResult = await pool.query('SELECT id, stored_filename, original_name, description, created_at FROM resources WHERE user_id = $1 ORDER BY created_at DESC', [req.session.userId]);
        res.render('dashboard', { logs: logsResult.rows, files: filesResult.rows, username: req.session.username, csrfToken: req.csrfToken() });
    } catch (e) { res.status(500).send('Erro ao buscar dados'); }
});

// --- [ALTERADO] UPLOAD COM CRIPTOGRAFIA ---
app.post('/upload', requireAuth, upload.single('file'), csrfProtection, async (req, res) => {
    try {
        if (!req.file) return res.status(400).send('Nenhum arquivo enviado');
        
        const description = req.body.description || '';

        // [NOVO] Criptografa o arquivo físico imediatamente
        await encryptFile(req.file.path);
        
        // [NOVO] Atualiza o tamanho do arquivo (pois o IV aumenta o tamanho)
        const stat = fs.statSync(req.file.path);

        await pool.query(
            'INSERT INTO resources (user_id, stored_filename, original_name, description, size) VALUES ($1,$2,$3,$4,$5)',
            [req.session.userId, req.file.filename, req.file.originalname, description, stat.size]
        );

        await audit(req.session.userId, 'file_upload_encrypted', { filename: sanitizeForLog(req.file.originalname) }, req.ip);
        writeLog(req.session.username, 'file_upload', { file: req.file.originalname, encrypted: true });

        res.redirect('/dashboard');
    } catch (e) {
        console.error('Upload error:', e);
        res.status(500).send('Erro no upload');
    }
});

// --- [ALTERADO] DOWNLOAD COM DESCRIPTOGRAFIA (GET) ---
app.get('/files/:id', requireAuth, async (req, res) => {
    try {
        const fileId = parseInt(req.params.id, 10);
        if (isNaN(fileId)) return res.status(400).send('ID inválido');

        const r = await pool.query('SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2', [fileId, req.session.userId]);
        if (!r.rowCount) return res.status(404).send('Arquivo não encontrado');

        const stored = r.rows[0].stored_filename;
        const webUser = req.session.username;
        let base = getWindowsUserHomeIfExists(webUser);
        if (!base) base = path.join(novosUsuariosRoot, webUser);
        
        const filepath = safeJoin(path.join(base, 'uploads'), stored);

        await audit(req.session.userId, 'file_download_decrypted', { id: fileId }, req.ip);
        
        // [NOVO] Usa a função de descriptografia em stream
        res.setHeader('Content-Disposition', `attachment; filename="${r.rows[0].original_name}"`);
        const decryptStream = getDecryptedFileStream(filepath);
        decryptStream.pipe(res);

    } catch (e) {
        console.error('Download error:', e);
        res.status(500).send('Erro ao servir arquivo');
    }
});

// --- [ALTERADO] DOWNLOAD COM DESCRIPTOGRAFIA (POST) ---
app.post('/files/download', requireAuth, csrfProtection, async (req, res) => {
    try {
        const fileId = parseInt(req.body.id, 10);
        if (isNaN(fileId)) return res.status(400).send('ID inválido');

        const r = await pool.query('SELECT stored_filename, original_name FROM resources WHERE id = $1 AND user_id = $2', [fileId, req.session.userId]);
        if (!r.rowCount) return res.status(404).send('Arquivo não encontrado');

        const stored = r.rows[0].stored_filename;
        const webUser = req.session.username;
        let base = getWindowsUserHomeIfExists(webUser);
        if (!base) base = path.join(novosUsuariosRoot, webUser);

        const filepath = safeJoin(path.join(base, 'uploads'), stored);

        await audit(req.session.userId, 'file_download_decrypted', { id: fileId }, req.ip);
        writeLog(req.session.username, 'file_download', { file: r.rows[0].original_name });

        // [NOVO] Stream descriptografado
        res.setHeader('Content-Disposition', `attachment; filename="${r.rows[0].original_name}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        
        const decryptStream = getDecryptedFileStream(filepath);
        decryptStream.pipe(res);

    } catch (err) {
        console.error('Download error:', err);
        res.status(500).send('Erro ao servir arquivo');
    }
});

app.post('/open-by-path', requireAuth, csrfProtection, async (req, res) => {
    try {
        const clientPath = req.body.clientPath;
        const webUser = req.session.username;
        const validated = validateClientPhysicalPath(webUser, clientPath);
        const stat = fs.statSync(validated);
        if (!stat.isFile()) return res.status(400).send('Caminho não é arquivo');
        await audit(req.session.userId, 'open_by_path', { basename: path.basename(validated) }, req.ip);
        res.setHeader('Content-Disposition', `inline; filename="${path.basename(validated)}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        const stream = fs.createReadStream(validated);
        stream.pipe(res);
    } catch (err) {
        console.warn('Tentativa de acesso inválido:', err.message);
        return res.status(400).send('Caminho inválido ou acesso negado');
    }
});

app.post('/import-by-path', requireAuth, csrfProtection, async (req, res) => {
    try {
        const clientPath = req.body.clientPath;
        const webUser = req.session.username;
        const description = req.body.description || '';
        const validated = validateClientPhysicalPath(webUser, clientPath);
        const stat = fs.statSync(validated);
        if (!stat.isFile()) return res.status(400).send('Caminho não é arquivo');

        // Prepara diretório
        let base = getWindowsUserHomeIfExists(webUser);
        if (!base) base = path.join(novosUsuariosRoot, webUser);
        const userUploadDir = path.join(base, 'uploads');
        mkdirSecureSync(userUploadDir);

        const ext = path.extname(validated) || '';
        const storedName = `${uuidv4()}${ext}`;
        const dest = path.join(userUploadDir, storedName);

        // Copia arquivo
        fs.copyFileSync(validated, dest); // Simplificado para copyFileSync para garantir atomicidade

        // [NOVO] Criptografa o arquivo importado também!
        await encryptFile(dest);
        const newSize = fs.statSync(dest).size;

        await pool.query(
            'INSERT INTO resources (user_id, stored_filename, original_name, description, size) VALUES ($1,$2,$3,$4,$5)',
            [req.session.userId, storedName, path.basename(validated), description || null, newSize]
        );

        await audit(req.session.userId, 'import_by_path_encrypted', { basename: path.basename(validated) }, req.ip);
        return res.redirect('/dashboard');
    } catch (err) {
        console.error('Erro import-by-path', err);
        res.status(400).send('Erro ao importar: ' + (err.message || ''));
    }
});

app.get('/search', requireAuth, csrfProtection, async (req, res) => {
    try {
        const query = req.query.q || '';
        let results = [];
        if (query.trim()) {
            results = await pool.query(
                'SELECT id, original_name, description, created_at FROM resources WHERE user_id = $1 AND (original_name ILIKE $2 OR description ILIKE $2) ORDER BY created_at DESC',
                [req.session.userId, `%${query}%`]
            );
            await audit(req.session.userId, 'search', { query: sanitizeForLog(query) }, req.ip);
        }
        res.render('search', { query: sanitizeForDisplay(query), results: results.rows || [], csrfToken: req.csrfToken() });
    } catch (e) { res.status(500).send('Erro na busca'); }
});

app.post('/logout', requireAuth, csrfProtection, async (req, res) => {
    const uid = req.session.userId;
    const uname = req.session.username;
    req.session.destroy(async err => {
        if (err) return res.status(500).send('Erro ao encerrar sessão');
        await audit(uid, 'logout', { username: sanitizeForLog(uname) }, req.ip);
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') return res.status(403).send('Formulário inválido (CSRF detectado).');
    next(err);
});

// LOGS DIÁRIOS E FLOOD (MANTIDOS)
const LOGS_DIR = path.join(__dirname, 'logs');
mkdirSecureSync(LOGS_DIR);
const BLACKLIST_FILE = path.join(LOGS_DIR, 'blacklist.json');
const FLOOD_THRESHOLD = 30;
const floodTracker = {};

function ensureBlacklist() { if (!fs.existsSync(BLACKLIST_FILE)) fs.writeFileSync(BLACKLIST_FILE, JSON.stringify([]), { mode: 0o600 }); }
function getBlacklist() { ensureBlacklist(); try { return JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8')); } catch { return []; } }
function addToBlacklist(username) {
    ensureBlacklist();
    const list = getBlacklist();
    if (!list.includes(username)) {
        list.push(username);
        fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(list, null, 2));
    }
}
function isBlacklisted(username) { return getBlacklist().includes(username); }
function formatDate(d = new Date()) {
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yyyy = d.getFullYear();
    return `${dd}-${mm}-${yyyy}`;
}
function cleanupOldLogs() {
    try {
        const files = fs.readdirSync(LOGS_DIR).filter(f => f.startsWith('log-') && f.endsWith('.txt'));
        const now = Date.now();
        for (const file of files) {
            const match = file.match(/log-(\d{2})-(\d{2})-(\d{4})\.txt/);
            if (!match) continue;
            const [_, dd, mm, yyyy] = match;
            const fileDate = new Date(`${yyyy}-${mm}-${dd}T00:00:00`);
            const diffDays = (now - fileDate.getTime()) / (1000 * 60 * 60 * 24);
            if (diffDays > 7) fs.unlinkSync(path.join(LOGS_DIR, file));
        }
    } catch (e) {}
}
function writeLog(username, eventType, details = {}) {
    try {
        mkdirSecureSync(LOGS_DIR);
        cleanupOldLogs();
        const today = formatDate();
        const baseFilename = isBlacklisted(username) ? `auditoria-${today}.txt` : `log-${today}.txt`;
        const logPath = path.join(LOGS_DIR, baseFilename);
        if (!fs.existsSync(logPath)) fs.writeFileSync(logPath, '', { mode: 0o600 });

        if (username) {
            const now = Date.now();
            if (!floodTracker[username]) floodTracker[username] = [];
            floodTracker[username].push(now);
            floodTracker[username] = floodTracker[username].filter(ts => now - ts < 60000);
            if (floodTracker[username].length > FLOOD_THRESHOLD && !isBlacklisted(username)) {
                addToBlacklist(username);
                const auditFile = path.join(LOGS_DIR, `auditoria-${today}.txt`);
                const auditMsg = `[${new Date().toISOString()}] USUÁRIO SUSPEITO: ${username}\n`;
                fs.appendFileSync(auditFile, auditMsg, { encoding: 'utf8' });
            }
        }
        const entry = `[${new Date().toISOString()}] USER=${username || 'anon'} EVENT=${eventType} DETAILS=${JSON.stringify(details)}\n`;
        fs.appendFileSync(logPath, entry, { encoding: 'utf8' });
    } catch (err) { console.error('[LOG ERROR]', err); }
}

// ------------------------------------------------------------------
// TRABALHO EXTRA ---- [NOVO] INICIALIZAÇÃO DO SERVIDOR COM TLS (HTTPS)
// ------------------------------------------------------------------
try {
    // Carrega os certificados gerados (cert.pem e key.pem)
    const sslOptions = {
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
    };

    // 1. Inicia o servidor principal em HTTPS (Porta 3000)
    https.createServer(sslOptions, app).listen(PORT, () => {
        console.log(`✅ Servidor Seguro (HTTPS) rodando em: https://localhost:${PORT}`);
    });

    // 2. Inicia o redirecionador HTTP (Porta 3001) para obrigar o uso de HTTPS
    http.createServer((req, res) => {
        // Redireciona tudo para HTTPS (Código 301)
        const target = `https://localhost:${PORT}${req.url}`;
        res.writeHead(301, { "Location": target });
        res.end();
    }).listen(HTTP_PORT, () => {
        console.log(`✅ Redirecionador HTTP rodando em: http://localhost:${HTTP_PORT}`);
    });

} catch (e) {
    console.error("\n❌ ERRO CRÍTICO: Certificados SSL (key.pem/cert.pem) não encontrados ou inválidos.");
    console.error("Motivo: " + e.message);
    console.error("A aplicação não pode iniciar no modo seguro. Verifique se 'node magica.js' foi executado.\n");
}