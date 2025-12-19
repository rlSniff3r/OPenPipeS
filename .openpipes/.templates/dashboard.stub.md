# 📊 Dashboard - {{targetName}}


```dataviewjs
const folder = dv.current().file.folder;
const alvoName = folder.split("/").pop();
const page = dv.page(`${folder}/${alvoName}.md`);
const baseUrl = page?.targetName ? `https://${page.targetName}` : "";
const services = page.t_services || [];
const closedPorts = page.t_Closed || [];
const filteredPorts = page.t_Filtered || [];

dv.header(2, "🧩 Serviços e Versões");

dv.table(
  ["Porta", "Serviço", "Versão", "TTL", "Fechada", "Filtrada"],
  services.map(item => {
    const parts = item.split(" ");
    const porta = parts[0] || "";
    const servico = parts[1] || "";
    const ttl = parts[4] || "";
    const versao = parts.slice(5).join(" ").trim();
    const isClosed = closedPorts.includes(porta) ? "✅" : "";
    const isFiltered = filteredPorts.includes(porta) ? "✅" : "";
    return [porta, servico, versao, ttl, isClosed, isFiltered];
  })
);

// ════════════════════════════════════════════════════════════════════════════
// SEÇÃO: IDENTIDADES COLETADAS (LOOT)
// ════════════════════════════════════════════════════════════════════════════

dv.header(2, "🔐 Identidades Coletadas");

// Define o caminho do arquivo identities.md no diretório local
const identitiesPath = dv.current().file.folder + "/identities.md";

// Verifica se o arquivo existe
const identitiesFile = dv.page(identitiesPath);

if (!identitiesFile) {
    dv.paragraph("⚠️ _Nenhuma identidade registrada ainda. Use o **Identities Manager** para adicionar._");
} else {
    // Lê o conteúdo do arquivo
    const fileContent = await dv.io.load(identitiesPath);
    
    // Extrai as linhas que contêm inline fields (começam com [type::)
    const identityLines = fileContent
        .split('\n')
        .filter(line => line.includes('[type::'));
    
    if (identityLines.length === 0) {
        dv.paragraph("⚠️ _Nenhuma identidade registrada ainda._");
    } else {
        // Função auxiliar para extrair valor de um campo inline
        const extractField = (line, fieldName) => {
            const regex = new RegExp(`\[${fieldName}::\s*([^\]]+)\]`);
            const match = line.match(regex);
            return match ? match[1].trim() : "-";
        };
        
        // Processa cada linha e extrai os campos
        const identities = identityLines.map(line => {
            return {
                type: extractField(line, 'type'),
                user: extractField(line, 'user'),
                password: extractField(line, 'password'),
                hash: extractField(line, 'hash'),
                format: extractField(line, 'format'),
                address: extractField(line, 'address'),
                source: extractField(line, 'source'),
                notes: extractField(line, 'notes')
            };
        });
        
        // Agrupa por tipo
        const groupedByType = identities.reduce((acc, identity) => {
            if (!acc[identity.type]) {
                acc[identity.type] = [];
            }
            acc[identity.type].push(identity);
            return acc;
        }, {});
        
        // Renderiza tabelas por tipo
        for (const [type, items] of Object.entries(groupedByType)) {
            // Define o ícone e título por tipo
            let icon = "🔑";
            let title = type.charAt(0).toUpperCase() + type.slice(1);
            
            if (type === "credential") {
                icon = "🔐";
                title = "Credenciais";
            } else if (type === "hash") {
                icon = "🔒";
                title = "Hashes";
            } else if (type === "email") {
                icon = "📧";
                title = "E-mails";
            } else if (type === "user") {
                icon = "👤";
                title = "Usuários";
            }
            
            dv.header(3, `${icon} ${title} (${items.length})`);
            
            // Define as colunas baseadas no tipo
            if (type === "credential") {
                dv.table(
                    ["Usuário", "Senha", "Endereço", "Fonte"],
                    items.map(i => [i.user, i.password, i.address, i.source])
                );
            } else if (type === "hash") {
                dv.table(
                    ["Usuário", "Hash", "Formato", "Endereço", "Fonte"],
                    items.map(i => [i.user, i.hash, i.format, i.address, i.source])
                );
            } else if (type === "email") {
                dv.table(
                    ["E-mail", "Fonte", "Observações"],
                    items.map(i => [i.address, i.source, i.notes])
                );
            } else if (type === "user") {
                dv.table(
                    ["Usuário", "Endereço", "Fonte", "Observações"],
                    items.map(i => [i.user, i.address, i.source, i.notes])
                );
            }
        }
        
        // Estatísticas gerais
        dv.header(3, "📊 Estatísticas");
        dv.paragraph(`**Total de identidades:** ${identities.length}`);
        
        const stats = Object.entries(groupedByType)
            .map(([type, items]) => `- **${type}**: ${items.length}`)
            .join('\n');
        dv.paragraph(stats);
    }
}

// Parser do httpx.md com deduplicação, filtro de status e limpeza de URL
const httpxPath = `${folder}/httpx.md`;
let httpxFile = app.vault.getAbstractFileByPath(httpxPath);

if (httpxFile) {
  const raw = await app.vault.read(httpxFile);
  const lines = raw.split("\n").filter(l => l.startsWith("|") && !l.includes("---"));

  const urlMap = new Map();

  for (let line of lines.slice(1)) {
    const cols = line.split("|").map(c => c.trim());
    if (cols.length < 7) continue;

    let url = cols[2];
    const status = cols[5];
    const title = cols[6];

    if (!url || !title || title === "-") continue;

    const match = status.match(/^\d+/);
    const statusCode = match ? parseInt(match[0]) : null;
    if (![200, 401, 403].includes(statusCode)) continue;

    // Limpa porta padrão da URL
    url = url.replace(/^http:\/\/([^\/:]+):80\b/, "http://$1");
    url = url.replace(/^https:\/\/([^\/:]+):443\b/, "https://$1");

    // Remove barra final
    url = url.replace(/\/$/, "");

    if (!urlMap.has(url)) {
      urlMap.set(url, title);
    }
  }

  if (urlMap.size > 0) {
    dv.paragraph("## 🔗 [[endpoints.md|Endpoints Mapeados:]]");
    for (let [url, title] of Array.from(urlMap.entries()).sort((a, b) => a[0].localeCompare(b[0]))) {
      dv.paragraph(`- [${url}](${url}) — **${title}**`);
    }
  } else {
    dv.paragraph("⚠️ Nenhum endpoint com status 200, 401 ou 403 e título encontrado no httpx.md.");
  }
} else {
  dv.paragraph("❌ Arquivo httpx.md não encontrado.");
}


dv.header(1, "☑️ Tarefas Pendentes");
dv.taskList(
  dv.pages(`"${folder}"`)
    .where(p => p.file.tasks && p.file.tasks.length > 0)
    .flatMap(p => p.file.tasks)
    .filter(t => !t.completed)
);

```
