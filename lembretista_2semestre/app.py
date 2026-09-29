from http.server import HTTPServer, SimpleHTTPRequestHandler
from http.cookies import SimpleCookie
import sqlite3
import json
import hashlib
import secrets
from urllib.parse import urlparse

DB = "lembretista.db"

SESSOES = {}


def conectar():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def criar_banco():
    conn = conectar()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tarefas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            titulo TEXT NOT NULL,
            descricao TEXT,
            data TEXT NOT NULL,
            hora TEXT NOT NULL,
            status TEXT DEFAULT 'pendente',
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    """)
    conn.commit()
    conn.close()


def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()


CONTEUDO_JS = r"""
async function enviar(url, dados) {
    const r = await fetch(url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        credentials: "same-origin",
        body: JSON.stringify(dados)
    });
    return r.json();
}

function mostrarLogin() {
    document.getElementById("loginForm").classList.remove("oculto");
    document.getElementById("cadastroForm").classList.add("oculto");
}

function mostrarCadastro() {
    document.getElementById("loginForm").classList.add("oculto");
    document.getElementById("cadastroForm").classList.remove("oculto");
}

async function cadastro() {
    const r = await enviar("/api/cadastro", {
        nome: document.getElementById("cadNome").value,
        email: document.getElementById("cadEmail").value,
        senha: document.getElementById("cadSenha").value
    });
    document.getElementById("mensagem").textContent =
        r.sucesso ? "Cadastro realizado!" : r.erro;
    if (r.sucesso) mostrarLogin();
}

async function login() {
    const r = await enviar("/api/login", {
        email: document.getElementById("loginEmail").value,
        senha: document.getElementById("loginSenha").value
    });
    if (!r.sucesso) {
        document.getElementById("mensagem").textContent = r.erro;
        return;
    }
    entrarNoApp(r.nome);
}

function entrarNoApp(nome) {
    document.getElementById("nomeUsuario").textContent = nome;
    document.getElementById("telaAuth").classList.add("oculto");
    document.getElementById("telaApp").classList.remove("oculto");
    carregar();
}

async function logout() {
    await enviar("/api/logout", {});
    location.href = "/";
}

async function adicionar() {
    const r = await enviar("/api/tarefa", {
        titulo: document.getElementById("titulo").value,
        descricao: document.getElementById("descricao").value,
        data: document.getElementById("data").value,
        hora: document.getElementById("hora").value
    });
    if (!r.sucesso) { alert(r.erro); return; }
    document.getElementById("titulo").value = "";
    document.getElementById("descricao").value = "";
    carregar();
}

async function acao(url, id) {
    await enviar(url, {id: id});
    carregar();
}

async function carregar() {
    const r = await fetch("/api/tarefas", { credentials: "same-origin" });
    const dados = await r.json();
    if (dados.erro) return;

    const pendentes = dados.tarefas.filter(t => t.status === "pendente");
    const concluidas = dados.tarefas.filter(t => t.status === "concluida");
    const lixeira   = dados.tarefas.filter(t => t.status === "lixeira");

    document.getElementById("qPendentes").textContent  = pendentes.length;
    document.getElementById("qConcluidas").textContent = concluidas.length;
    document.getElementById("qLixeira").textContent    = lixeira.length;

    document.getElementById("pendentes").innerHTML  = criarLista(pendentes,  "pendente");
    document.getElementById("concluidas").innerHTML = criarLista(concluidas, "concluida");
    document.getElementById("lixeira").innerHTML    = criarLista(lixeira,    "lixeira");
}

function criarLista(lista, tipo) {
    if (!lista.length) return "<p class='vazio'>Nenhum lembrete aqui.</p>";
    return lista.map(t => `
        <div class="tarefa ${tipo}">
            <h3>${t.titulo}</h3>
            <p>${t.descricao || ""}</p>
            <small>${t.data} às ${t.hora}</small>
            <div class="acoes">
                ${tipo === "pendente" ? `
                    <button onclick="acao('/api/concluir', ${t.id})">✓ Concluir</button>
                    <button onclick="acao('/api/lixeira', ${t.id})">🗑 Excluir</button>` : ""}
                ${tipo === "concluida" ? `
                    <button onclick="acao('/api/lixeira', ${t.id})">🗑 Excluir</button>` : ""}
                ${tipo === "lixeira" ? `
                    <button onclick="acao('/api/restaurar', ${t.id})">↩ Restaurar</button>
                    <button onclick="acao('/api/excluir', ${t.id})">Excluir definitivamente</button>` : ""}
            </div>
        </div>
    `).join("");
}

function mostrarAba(aba) {
    ["pendentes", "concluidas", "lixeira"].forEach(nome => {
        document.getElementById(nome).classList.add("oculto");
    });
    document.getElementById(aba).classList.remove("oculto");
}

async function verificarSessao() {
    try {
        const r = await fetch("/api/sessao", { credentials: "same-origin" });
        const d = await r.json();
        if (d.logado) {
            entrarNoApp(d.nome);
            return;
        }
    } catch (e) { /* ignora */ }
    document.getElementById("telaAuth").classList.remove("oculto");
}

mostrarAba("pendentes");
verificarSessao();
"""


class Servidor(SimpleHTTPRequestHandler):
    def responder(self, dados, set_cookie=None):
        corpo = json.dumps(dados, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(corpo)

    def receber(self):
        tamanho = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(tamanho).decode()) if tamanho else {}

    def usuario_atual(self):
        """Lê o cookie de sessão e retorna o usuario_id correspondente."""
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            token = cookie.get("sessao")
            if not token:
                return None
            return SESSOES.get(token.value)
        except Exception:
            return None

    def do_GET(self):
        caminho = urlparse(self.path).path

        if caminho == "/static/js/app.js":
            corpo = CONTEUDO_JS.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)
            return

        if caminho == "/api/sessao":
            uid = self.usuario_atual()
            if not uid:
                return self.responder({"logado": False})
            conn = conectar()
            u = conn.execute("SELECT nome FROM usuarios WHERE id = ?", (uid,)).fetchone()
            conn.close()
            if not u:
                return self.responder({"logado": False})
            return self.responder({"logado": True, "nome": u["nome"]})

        paginas = {
            "/": "/templates/index.html",
            "/dashboard": "/templates/dashboard.html",
            "/gamificacao": "/templates/gamificacao.html"
        }
        if caminho in paginas:
            self.path = paginas[caminho]
            return super().do_GET()

        uid = self.usuario_atual()

        if caminho == "/api/tarefas":
            if not uid:
                return self.responder({"erro": "Faça login primeiro."})
            conn = conectar()
            tarefas = conn.execute(
                "SELECT * FROM tarefas WHERE usuario_id = ? ORDER BY data, hora",
                (uid,)
            ).fetchall()
            conn.close()
            return self.responder({"tarefas": [dict(t) for t in tarefas]})

        if caminho == "/api/dashboard":
            if not uid:
                return self.responder({"erro": "Faça login primeiro."})
            conn = conectar()
            total = conn.execute("SELECT COUNT(*) FROM tarefas WHERE usuario_id = ?", (uid,)).fetchone()[0]
            pendentes = conn.execute("SELECT COUNT(*) FROM tarefas WHERE usuario_id = ? AND status = 'pendente'", (uid,)).fetchone()[0]
            concluidas = conn.execute("SELECT COUNT(*) FROM tarefas WHERE usuario_id = ? AND status = 'concluida'", (uid,)).fetchone()[0]
            lixeira = conn.execute("SELECT COUNT(*) FROM tarefas WHERE usuario_id = ? AND status = 'lixeira'", (uid,)).fetchone()[0]
            conn.close()
            return self.responder({"total": total, "pendentes": pendentes, "concluidas": concluidas, "lixeira": lixeira})

        if caminho == "/api/gamificacao":
            if not uid:
                return self.responder({"erro": "Faça login primeiro."})
            conn = conectar()
            concluidas = conn.execute("SELECT COUNT(*) FROM tarefas WHERE usuario_id = ? AND status = 'concluida'", (uid,)).fetchone()[0]
            total = conn.execute("SELECT COUNT(*) FROM tarefas WHERE usuario_id = ?", (uid,)).fetchone()[0]
            conn.close()
            pontos = concluidas * 10
            nivel = (pontos // 50) + 1
            pontos_proximo = nivel * 50
            pontos_nivel = pontos - ((nivel - 1) * 50)
            conquistas = [
                {"nome": "Primeiro passo",        "descricao": "Conclua sua primeira tarefa.", "liberada": concluidas >= 1},
                {"nome": "Organizado",            "descricao": "Conclua 5 tarefas.",           "liberada": concluidas >= 5},
                {"nome": "Mestre da organização", "descricao": "Conclua 10 tarefas.",          "liberada": concluidas >= 10},
                {"nome": "Criador de tarefas",    "descricao": "Crie 10 tarefas.",             "liberada": total >= 10},
            ]
            return self.responder({
                "pontos": pontos, "nivel": nivel,
                "pontos_nivel": pontos_nivel, "pontos_proximo": pontos_proximo,
                "concluidas": concluidas, "conquistas": conquistas
            })

        return super().do_GET()

    def do_POST(self):
        caminho = urlparse(self.path).path
        dados = self.receber()

        if caminho == "/api/cadastro":
            nome = dados.get("nome", "").strip()
            email = dados.get("email", "").strip()
            senha = dados.get("senha", "")
            if not nome or not email or not senha:
                return self.responder({"erro": "Preencha todos os campos."})
            try:
                conn = conectar()
                conn.execute("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)",
                             (nome, email, hash_senha(senha)))
                conn.commit(); conn.close()
                return self.responder({"sucesso": True})
            except sqlite3.IntegrityError:
                return self.responder({"erro": "E-mail já cadastrado."})

        if caminho == "/api/login":
            email = dados.get("email", "").strip()
            senha = hash_senha(dados.get("senha", ""))
            conn = conectar()
            usuario = conn.execute("SELECT * FROM usuarios WHERE email = ? AND senha = ?",
                                   (email, senha)).fetchone()
            conn.close()
            if not usuario:
                return self.responder({"erro": "E-mail ou senha incorretos."})
            token = secrets.token_hex(16)
            SESSOES[token] = usuario["id"]
            cookie = f"sessao={token}; Path=/; HttpOnly; SameSite=Lax"
            return self.responder({"sucesso": True, "nome": usuario["nome"]}, set_cookie=cookie)

        if caminho == "/api/logout":
            cookie_header = self.headers.get("Cookie", "")
            try:
                cookie = SimpleCookie()
                cookie.load(cookie_header)
                token = cookie.get("sessao")
                if token and token.value in SESSOES:
                    del SESSOES[token.value]
            except Exception:
                pass
            expira = "sessao=; Path=/; Max-Age=0; SameSite=Lax"
            return self.responder({"sucesso": True}, set_cookie=expira)

        uid = self.usuario_atual()
        if not uid:
            return self.responder({"erro": "Faça login primeiro."})

        if caminho == "/api/tarefa":
            titulo = dados.get("titulo", "").strip()
            descricao = dados.get("descricao", "").strip()
            data = dados.get("data", "")
            hora = dados.get("hora", "")
            if not titulo or not data or not hora:
                return self.responder({"erro": "Título, data e hora são obrigatórios."})
            conn = conectar()
            conn.execute("""
                INSERT INTO tarefas (usuario_id, titulo, descricao, data, hora, status)
                VALUES (?, ?, ?, ?, ?, 'pendente')
            """, (uid, titulo, descricao, data, hora))
            conn.commit(); conn.close()
            return self.responder({"sucesso": True})

        tarefa_id = dados.get("id")

        if caminho == "/api/concluir":
            conn = conectar()
            conn.execute("UPDATE tarefas SET status = 'concluida' WHERE id = ? AND usuario_id = ?",
                         (tarefa_id, uid))
            conn.commit(); conn.close()
            return self.responder({"sucesso": True})

        if caminho == "/api/lixeira":
            conn = conectar()
            conn.execute("UPDATE tarefas SET status = 'lixeira' WHERE id = ? AND usuario_id = ?",
                         (tarefa_id, uid))
            conn.commit(); conn.close()
            return self.responder({"sucesso": True})

        if caminho == "/api/restaurar":
            conn = conectar()
            conn.execute("UPDATE tarefas SET status = 'pendente' WHERE id = ? AND usuario_id = ?",
                         (tarefa_id, uid))
            conn.commit(); conn.close()
            return self.responder({"sucesso": True})

        if caminho == "/api/excluir":
            conn = conectar()
            conn.execute("DELETE FROM tarefas WHERE id = ? AND usuario_id = ?",
                         (tarefa_id, uid))
            conn.commit(); conn.close()
            return self.responder({"sucesso": True})

        return self.responder({"erro": "Ação não encontrada."})


criar_banco()
print("Lembretista rodando em: http://localhost:8000")
HTTPServer(("", 8000), Servidor).serve_forever()