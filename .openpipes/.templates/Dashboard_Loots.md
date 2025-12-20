# 🏴‍☠️ Loot Box - Global Credential Center
> Visão consolidada de todas as credenciais capturadas no projeto.

```dataviewjs
// --- CONFIGURAÇÃO ---
const DEBUG = false; // Mude para true se a tabela não aparecer
const FILENAME = "identities"; // Nome do arquivo buscado

// --- FUNÇÃO AUXILIAR DE EXTRAÇÃO (REGEX FLEXÍVEL) ---
// Extrai o valor de [chave::valor] independentemente da posição na linha
function extractField(line, key) {
    // Regex: Procura por [key:: qualquer_coisa ] (non-greedy)
    const regex = new RegExp(`\\[${key}::(.*?)\\]`, "i");
    const match = line.match(regex);
    return match ? match[1].trim() : null;
}

// --- BUSCA DE ARQUIVOS ---
// Busca em todo o vault, mas filtra apenas arquivos "identities" que estejam dentro de "Alvos"
let pages = dv.pages()
    .where(p => p.file.name === FILENAME && p.file.path.includes("Alvos"));

if (DEBUG) dv.paragraph(`🔍 DEBUG: Encontrei ${pages.length} arquivos 'identities.md'.`);

let rows = [];

// --- PROCESSAMENTO ---
for (let p of pages) {
    // Ler conteúdo bruto
    let content = await dv.io.load(p.file.path);
    if (!content) {
        if (DEBUG) dv.paragraph(`⚠️ DEBUG: Falha ao ler ${p.file.path}`);
        continue;
    }

    let lines = content.split("\n");
    
    // Nome do Alvo (Pasta Pai)
    let pathParts = p.file.folder.split("/");
    let alvoName = pathParts[pathParts.length - 1]; // Pega o último nome da pasta (IP)
    let alvoLink = `[[Dashboard_${alvoName}|${alvoName}]]`;

    for (let line of lines) {
        // Filtro básico: A linha deve ser uma credencial
        if (!line.includes("[type::credential]")) continue;

        // Extração Atômica (Campo a Campo)
        let user = extractField(line, "user") || "N/A";
        let pass = extractField(line, "password") || "N/A";
        let targetIP = extractField(line, "target") || "N/A";
        let source = extractField(line, "source") || "N/A";

        // Formatação da Senha (Truncar se for hash gigante)
        let passDisplay = pass;
        if (pass.length > 25 && !pass.includes(" ")) { // Assume hash se for longo e sem espaço
             passDisplay = pass.substring(0, 10) + "...";
        }

        rows.push([alvoLink, user, `\`${passDisplay}\``, targetIP, source]);
    }
}

// --- RENDERIZAÇÃO ---
if (rows.length === 0) {
    dv.paragraph("🚫 **Nenhuma credencial capturada ainda.** (Ou verifique se o formato no identities.md está correto)");
    if (DEBUG) dv.paragraph("ℹ️ DEBUG: Verifique se o identities.md contém '[type::credential]'");
} else {
    dv.header(3, `🔓 Credenciais Encontradas: ${rows.length}`);
    dv.table(
        ["Alvo", "Usuário", "Senha / Hash", "Alvo (IP)", "Fonte"], 
        rows
    );
}