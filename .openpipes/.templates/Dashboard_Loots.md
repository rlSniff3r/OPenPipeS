---
tipo: dashboard
projeto: {{proj_name}}
---

# 🏆 Dashboard Central - Loots do Projeto

> [!info] Sobre esta Dashboard
> Esta dashboard agrega **todas as identidades coletadas** em todos os alvos do projeto. Use-a para ter uma visão consolidada do loot obtido durante o pentest.

---

```dataviewjs
// ════════════════════════════════════════════════════════════════════════════
// DASHBOARD CENTRAL DE LOOT - OpenPipeS
// Agrega todas as identidades de todos os alvos do projeto
// ════════════════════════════════════════════════════════════════════════════

dv.header(2, "🔐 Todas as Identidades do Projeto");

// Define o caminho base dos alvos
const alvosPath = "Pentest/Alvos";

// Busca todos os arquivos identities.md em subpastas de Alvos/
const identitiesFiles = dv.pages(`"${alvosPath}"`)
    .where(p => p.file.name === "identities");

if (identitiesFiles.length === 0) {
    dv.paragraph("⚠️ _Nenhum arquivo de identidades encontrado. Use o **Identities Manager** para adicionar._");
} else {
    // Array para armazenar todas as identidades de todos os alvos
    let allIdentities = [];
    
    // Função auxiliar para extrair valor de um campo inline
    const extractField = (line, fieldName) => {
        const regex = new RegExp(`\[${fieldName}::\s*([^\]]+)\]`);
        const match = line.match(regex);
        return match ? match[1].trim() : "-";
    };
    
    // Processa cada arquivo identities.md encontrado
    for (const file of identitiesFiles) {
        const filePath = file.file.path;
        const fileContent = await dv.io.load(filePath);
        
        // Extrai o nome do alvo do caminho (pasta pai)
        const targetName = file.file.folder.split('/').pop();
        
        // Extrai as linhas que contêm inline fields
        const identityLines = fileContent
            .split('\n')
            .filter(line => line.includes('[type::'));
        
        // Processa cada linha
        for (const line of identityLines) {
            const identity = {
                target: extractField(line, 'target') !== "-" ? extractField(line, 'target') : targetName,
                type: extractField(line, 'type'),
                user: extractField(line, 'user'),
                password: extractField(line, 'password'),
                hash: extractField(line, 'hash'),
                format: extractField(line, 'format'),
                address: extractField(line, 'address'),
                source: extractField(line, 'source'),
                notes: extractField(line, 'notes')
            };
            
            allIdentities.push(identity);
        }
    }
    
    if (allIdentities.length === 0) {
        dv.paragraph("⚠️ _Nenhuma identidade registrada ainda._");
    } else {
        // ════════════════════════════════════════════════════════════════
        // SEÇÃO 1: VISÃO GERAL POR ALVO
        // ════════════════════════════════════════════════════════════════
        
        dv.header(3, "📊 Visão Geral por Alvo");
        
        // Agrupa por alvo
        const groupedByTarget = allIdentities.reduce((acc, identity) => {
            if (!acc[identity.target]) {
                acc[identity.target] = [];
            }
            acc[identity.target].push(identity);
            return acc;
        }, {});
        
        // Cria tabela de resumo por alvo
        const targetSummary = Object.entries(groupedByTarget).map(([target, items]) => {
            const credentials = items.filter(i => i.type === "credential").length;
            const hashes = items.filter(i => i.type === "hash").length;
            const emails = items.filter(i => i.type === "email").length;
            const users = items.filter(i => i.type === "user").length;
            
            return [
                `[[${target}/${target}|${target}]]`,
                items.length,
                credentials,
                hashes,
                emails,
                users
            ];
        });
        
        dv.table(
            ["Alvo", "Total", "🔐 Credenciais", "🔒 Hashes", "📧 E-mails", "👤 Usuários"],
            targetSummary
        );
        
        // ════════════════════════════════════════════════════════════════
        // SEÇÃO 2: TODAS AS IDENTIDADES AGRUPADAS POR TIPO
        // ════════════════════════════════════════════════════════════════
        
        dv.header(3, "🗂️ Todas as Identidades (Agrupadas por Tipo)");
        
        // Agrupa por tipo
        const groupedByType = allIdentities.reduce((acc, identity) => {
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
            
            dv.header(4, `${icon} ${title} (${items.length})`);
            
            // Define as colunas baseadas no tipo
            if (type === "credential") {
                dv.table(
                    ["Alvo", "Usuário", "Senha", "Endereço", "Fonte"],
                    items.map(i => [
                        `[[${i.target}/${i.target}|${i.target}]]`,
                        i.user,
                        i.password,
                        i.address,
                        i.source
                    ])
                );
            } else if (type === "hash") {
                dv.table(
                    ["Alvo", "Usuário", "Hash", "Formato", "Endereço", "Fonte"],
                    items.map(i => [
                        `[[${i.target}/${i.target}|${i.target}]]`,
                        i.user,
                        i.hash,
                        i.format,
                        i.address,
                        i.source
                    ])
                );
            } else if (type === "email") {
                dv.table(
                    ["Alvo", "E-mail", "Fonte", "Observações"],
                    items.map(i => [
                        `[[${i.target}/${i.target}|${i.target}]]`,
                        i.address,
                        i.source,
                        i.notes
                    ])
                );
            } else if (type === "user") {
                dv.table(
                    ["Alvo", "Usuário", "Endereço", "Fonte", "Observações"],
                    items.map(i => [
                        `[[${i.target}/${i.target}|${i.target}]]`,
                        i.user,
                        i.address,
                        i.source,
                        i.notes
                    ])
                );
            }
        }
        
        // ════════════════════════════════════════════════════════════════
        // SEÇÃO 3: ESTATÍSTICAS GLOBAIS
        // ════════════════════════════════════════════════════════════════
        
        dv.header(3, "📈 Estatísticas Globais");
        
        const totalTargets = Object.keys(groupedByTarget).length;
        const totalIdentities = allIdentities.length;
        
        dv.paragraph(`**Total de alvos com loot:** ${totalTargets}`);
        dv.paragraph(`**Total de identidades coletadas:** ${totalIdentities}`);
        
        const typeStats = Object.entries(groupedByType)
            .map(([type, items]) => `- **${type}**: ${items.length}`)
            .join('\n');
        dv.paragraph(typeStats);
        
        // Estatísticas de fontes
        const sourceStats = allIdentities.reduce((acc, identity) => {
            if (!acc[identity.source]) {
                acc[identity.source] = 0;
            }
            acc[identity.source]++;
            return acc;
        }, {});
        
        dv.header(4, "🔍 Por Fonte");
        const sourceList = Object.entries(sourceStats)
            .sort((a, b) => b[1] - a[1])
            .map(([source, count]) => `- **${source}**: ${count}`)
            .join('\n');
        dv.paragraph(sourceList);
    }
}