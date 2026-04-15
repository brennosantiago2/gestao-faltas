require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createClient } = require('@libsql/client');

const app = express();
const SECRET_KEY = process.env.SECRET_KEY || "santiago_seguranca_maxima_2026";

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Conexão com o Banco de Dados em Nuvem (Turso)
const db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
});

// Inicialização das Tabelas no Turso
async function inicializarBanco() {
    await db.execute("CREATE TABLE IF NOT EXISTS funcionarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT, funcao TEXT)");
    await db.execute("CREATE TABLE IF NOT EXISTS faltas (id INTEGER PRIMARY KEY AUTOINCREMENT, funcionario_id INTEGER, data TEXT, dia_semana TEXT, observacao TEXT, FOREIGN KEY(funcionario_id) REFERENCES funcionarios(id))");
    await db.execute("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");

    const hashBrenno = bcrypt.hashSync("brenno123?", 10);
    const hashDilson = bcrypt.hashSync("32254722", 10);

    const checkBrenno = await db.execute({ sql: "SELECT * FROM usuarios WHERE username = ?", args: ['brenno'] });
    if (checkBrenno.rows.length === 0) {
        await db.execute({ sql: "INSERT INTO usuarios (username, password) VALUES (?, ?)", args: ['brenno', hashBrenno] });
    }
    const checkDilson = await db.execute({ sql: "SELECT * FROM usuarios WHERE username = ?", args: ['dilson'] });
    if (checkDilson.rows.length === 0) {
        await db.execute({ sql: "INSERT INTO usuarios (username, password) VALUES (?, ?)", args: ['dilson', hashDilson] });
    }
}
inicializarBanco();

// --- LOGIN ---
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await db.execute({ sql: "SELECT * FROM usuarios WHERE username = ?", args: [username] });
        const user = result.rows[0];
        
        if (!user) return res.status(401).json({ error: "Usuário não encontrado" });

        const senhaValida = bcrypt.compareSync(password, user.password);
        if (!senhaValida) return res.status(401).json({ error: "Senha incorreta" });

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '8h' });
        res.cookie('token', token, { httpOnly: true });
        res.json({ message: "Logado!" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: "Deslogado" });
});

const verificarSessao = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Acesso Negado" });
    try {
        jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) { res.status(401).json({ error: "Sessão expirada" }); }
};

app.get('/verificar-sessao', verificarSessao, (req, res) => { res.json({ logado: true }); });

// --- FUNCIONÁRIOS ---
app.post('/funcionarios', verificarSessao, async (req, res) => {
    try {
        const { nome, funcao } = req.body;
        const result = await db.execute({ sql: "INSERT INTO funcionarios (nome, funcao) VALUES (?, ?)", args: [nome, funcao] });
        res.json({ id: Number(result.lastInsertRowid), nome, funcao });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/funcionarios', verificarSessao, async (req, res) => {
    try {
        const result = await db.execute("SELECT * FROM funcionarios");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/funcionarios/:id', verificarSessao, async (req, res) => {
    try {
        const { nome, funcao } = req.body;
        await db.execute({ sql: "UPDATE funcionarios SET nome = ?, funcao = ? WHERE id = ?", args: [nome, funcao, req.params.id] });
        res.json({ message: "Atualizado" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/funcionarios/:id', verificarSessao, async (req, res) => {
    try {
        await db.execute({ sql: "DELETE FROM faltas WHERE funcionario_id = ?", args: [req.params.id] });
        await db.execute({ sql: "DELETE FROM funcionarios WHERE id = ?", args: [req.params.id] });
        res.json({ message: "Deletado" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- FALTAS ---
app.post('/faltas', verificarSessao, async (req, res) => {
    try {
        const { funcionario_id, data, dia_semana } = req.body;
        const result = await db.execute({ sql: "INSERT INTO faltas (funcionario_id, data, dia_semana, observacao) VALUES (?, ?, ?, '')", args: [funcionario_id, data, dia_semana] });
        res.json({ id: Number(result.lastInsertRowid) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/faltas', verificarSessao, async (req, res) => {
    try {
        const { mes, funcionario_id, pagina = 1 } = req.query;
        const limite = 15;
        const offset = (pagina - 1) * limite;
        
        let sql = `SELECT faltas.id, funcionarios.nome, funcionarios.funcao, faltas.data, faltas.dia_semana, faltas.observacao FROM faltas JOIN funcionarios ON faltas.funcionario_id = funcionarios.id WHERE 1=1`;
        let args = [];

        if (funcionario_id) { sql += ` AND faltas.funcionario_id = ?`; args.push(funcionario_id); }
        if (mes) { sql += ` AND faltas.data LIKE ?`; args.push(`%${mes}`); }
        
        sql += ` ORDER BY substr(faltas.data, 7, 4) DESC, substr(faltas.data, 4, 2) DESC, substr(faltas.data, 1, 2) DESC, faltas.id DESC LIMIT ? OFFSET ?`;
        args.push(limite, offset);

        const result = await db.execute({ sql, args });
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/faltas/:id', verificarSessao, async (req, res) => {
    try {
        const { observacao } = req.body;
        await db.execute({ sql: "UPDATE faltas SET observacao = ? WHERE id = ?", args: [observacao, req.params.id] });
        res.json({ message: "Atualizado" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/faltas/:id', verificarSessao, async (req, res) => {
    try {
        await db.execute({ sql: "DELETE FROM faltas WHERE id = ?", args: [req.params.id] });
        res.json({ message: "Deletada" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/exportar', verificarSessao, async (req, res) => {
    try {
        const { mes, funcionario_id } = req.query;
        let sql = `SELECT funcionarios.nome, funcionarios.funcao, faltas.data, faltas.dia_semana, faltas.observacao FROM faltas JOIN funcionarios ON faltas.funcionario_id = funcionarios.id WHERE 1=1`;
        let args = [];

        if (funcionario_id) { sql += ` AND faltas.funcionario_id = ?`; args.push(funcionario_id); }
        if (mes) { sql += ` AND faltas.data LIKE ?`; args.push(`%${mes}`); }
        
        sql += ` ORDER BY funcionarios.nome ASC, substr(faltas.data, 7, 4) DESC, substr(faltas.data, 4, 2) DESC, substr(faltas.data, 1, 2) DESC`;

        const result = await db.execute({ sql, args });
        const rows = result.rows;

        let tituloMes = "";
        if (mes) {
            const [mesNum, ano] = mes.split('/');
            const mesesNomes = { '01':'JANEIRO', '02':'FEVEREIRO', '03':'MARÇO', '04':'ABRIL', '05':'MAIO', '06':'JUNHO', '07':'JULHO', '08':'AGOSTO', '09':'SETEMBRO', '10':'OUTUBRO', '11':'NOVEMBRO', '12':'DEZEMBRO' };
            tituloMes = ` DE ${mesesNomes[mesNum]} -`;
        } else { tituloMes = " -"; }

        let texto = `=== RELATORIO DE FALTAS${tituloMes} SANTIAGO ESTRUTURAS METALICAS ===\n\n`;
        
        if (rows.length === 0) {
            texto += "Nenhuma falta registrada para o filtro selecionado.\n";
        } else {
            const faltasAgrupadas = {};
            rows.forEach(f => {
                const chaveFuncionario = `Funcionario: ${f.nome} (${f.funcao})`;
                if (!faltasAgrupadas[chaveFuncionario]) faltasAgrupadas[chaveFuncionario] = [];
                let linha = `Data: ${f.data} - ${f.dia_semana}`;
                if (f.observacao && f.observacao.trim() !== '') linha += ` (Obs: ${f.observacao})`;
                faltasAgrupadas[chaveFuncionario].push(linha);
            });

            for (const [funcionario, listaDeFaltas] of Object.entries(faltasAgrupadas)) {
                texto += `${funcionario}\n`;
                listaDeFaltas.forEach(falta => texto += `${falta}\n`);
                texto += `\n`;
            }
        }

        res.setHeader('Content-disposition', 'attachment; filename=relatorio_faltas.txt');
        res.setHeader('Content-type', 'text/plain; charset=utf-8');
        res.send(texto);
    } catch (err) { res.status(500).send("Erro ao gerar relatório"); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));