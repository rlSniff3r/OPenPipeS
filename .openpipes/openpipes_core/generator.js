const PizZip = require("pizzip");
const Docxtemplater = require("docxtemplater");
const ImageModule = require("docxtemplater-image-module-free");
const expressions = require("angular-expressions");
const sizeOf = require("image-size");
const fs = require("fs");
const path = require("path");

// ── 1. Tratamento de Valores Nulos (Evita 'undefined' no DOCX) ──
expressions.filters.lower = function(input) {
    if(!input) return input;
    return input.toLowerCase();
}

expressions.filters.where = function(input, key, value) {
    // Filtra a lista baseada em uma chave e um valor exato
    if (!Array.isArray(input)) return [];
    return input.filter(item => item[key] === value);
}

function angularParser(tag) {
    if (tag === '.') {
        return { get: function(s){ return s;} };
    }
    const expr = expressions.compile(tag.replace(/(’|“|”|‘)/g, "'"));
    return {
        get: function(scope, context) {
            let obj = {};
            const scopeList = context.numContexts;
            for(let i = scopeList - 1; i >= 0; i--) {
                Object.assign(obj, context.getContextItem(i));
            }
            const result = expr(scope, obj);
            return result === undefined ? "" : result; // Retorna vazio se não existir
        }
    };
}

// Filtro para filtrar valor exato (já fizemos antes)
expressions.filters.where = function(input, key, value) {
    if (!Array.isArray(input)) return [];
    return input.filter(item => item[key] === value);
};

// 👇 NOVOS FILTROS DE ORDENAÇÃO AQUI 👇

// Ordena do MAIOR para o MENOR (Decrescente)
expressions.filters.sortByDesc = function(input, key) {
    if (!Array.isArray(input)) return [];
    return input.slice().sort((a, b) => {
        let valA = a[key] !== null && a[key] !== undefined ? a[key] : -999;
        let valB = b[key] !== null && b[key] !== undefined ? b[key] : -999;
        return valA < valB ? 1 : valA > valB ? -1 : 0;
    });
};

// Ordena do MENOR para o MAIOR (Crescente)
expressions.filters.sortByAsc = function(input, key) {
    if (!Array.isArray(input)) return [];
    return input.slice().sort((a, b) => {
        let valA = a[key] !== null && a[key] !== undefined ? a[key] : -999;
        let valB = b[key] !== null && b[key] !== undefined ? b[key] : -999;
        return valA > valB ? 1 : valA < valB ? -1 : 0;
    });
};
// 👆 FIM DOS NOVOS FILTROS 👆

// ── 2. Módulo de Imagem (Aspect Ratio Perfeito) ──
const imageOpts = {
    centered: false,
    fileType: "docx",
    getImage: function(tagValue) {
        // Previne erro se a tag de imagem vier vazia (ex: sem logo)
        if (!tagValue) {
            return Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", "base64"); // Pixel transparente
        }

        const imgPath = path.resolve(tagValue);
        
        try {
            // Verifica se existe E se é um arquivo (evita erro de tentar ler diretório)
            if (fs.existsSync(imgPath) && fs.statSync(imgPath).isFile()) {
                return fs.readFileSync(imgPath);
            }
        } catch (e) {
            // Ignora falhas de leitura
        }
        
        console.warn(`[Aviso] Imagem não encontrada: ${imgPath}`);
        return Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", "base64");
    },

    getSize: function(img, tagValue, tagName) {
        try {
            // 1 cm = 37.8 pixels (Padrão de impressão do Word)
            
            // Trava exata para o Gráfico de Severidade (8.27 cm x 7.0 cm)
            if (tagName === "severity_chart") {
                return [Math.round(10.86 * 37.8), Math.round(8.77 * 37.8)];
            }
            
            // Trava exata para o Gráfico de CWE (10.0 cm x 7.0 cm)
            if (tagName === "cwe_chart") {
                return [Math.round(12.48 * 37.8), Math.round(8.75 * 37.8)];
            }

            // Para as outras imagens (evidências e screenshots), mantém o redimensionamento dinâmico
            const dimensions = sizeOf(img);
            const maxWidth = 600; 
            
            if (dimensions.width > maxWidth) {
                const ratio = dimensions.height / dimensions.width;
                const newHeight = Math.round(maxWidth * ratio);
                return [maxWidth, newHeight];
            }
            return [dimensions.width, dimensions.height];
            
        } catch (e) {
            console.warn(`[Aviso] Falha ao ler dimensões da imagem.`);
            return [600, 337];
        }
    }
};

// ── 3. Motor de Renderização ──
try {
    const templatePath = process.argv[2];
    const contextPath = process.argv[3];
    const outputPath = process.argv[4];

    const content = fs.readFileSync(path.resolve(templatePath), "binary");
    const zip = new PizZip(content);

    const imageModule = new ImageModule(imageOpts);

    const doc = new Docxtemplater(zip, {
        paragraphLoop: true,
        linebreaks: true,
        parser: angularParser,
        modules: [imageModule],
        nullGetter: () => "" // Fallback extra de segurança
    });

    const data = JSON.parse(fs.readFileSync(contextPath, "utf8"));
    doc.render(data);

    // ─── MÁGICA: PINTAR O FUNDO DA CÉLULA NATIVAMENTE ───
    try {
        let docXml = doc.getZip().file("word/document.xml").asText();
        
        // Procura por BGCOLOR-HEX em qualquer lugar dentro da célula inteira
        const cellRegex = /<w:tc>(?:(?!<w:tc>)[\s\S])*?BGCOLOR-([0-9A-Fa-f]{6})[\s\S]*?<\/w:tc>/g;
        
        docXml = docXml.replace(cellRegex, function(match, hex) {
            // 1. Remove a string mágica "BGCOLOR-HEX" do texto da célula (não afeta o resto do texto)
            let cleanMatch = match.replace(new RegExp(`BGCOLOR-${hex}`, 'g'), '');
            
            // 2. Remove as formatações de cor de fundo antigas (se houver)
            cleanMatch = cleanMatch.replace(/<w:shd[^>]*\/>/g, ''); 
            cleanMatch = cleanMatch.replace(/<w:shd[^>]*>[\s\S]*?<\/w:shd>/g, '');
            
            // 3. Injeta a cor do CVSS!
            if (cleanMatch.includes('<w:tcPr>')) {
                cleanMatch = cleanMatch.replace('<w:tcPr>', `<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="${hex}"/>`);
            } else {
                cleanMatch = cleanMatch.replace('<w:tc>', `<w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="${hex}"/></w:tcPr>`);
            }
            return cleanMatch;
        });

        doc.getZip().file("word/document.xml", docXml);
    } catch (err) {
        console.warn("[Aviso] Não foi possível injetar as cores nas células: ", err.message);
    }
    // ────────────────────────────────────────────────────