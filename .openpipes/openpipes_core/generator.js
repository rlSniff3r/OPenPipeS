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

// ── 2. Módulo de Imagem (Tamanho Original / Full Quality) ──
const imageOpts = {
    centered: false,
    fileType: "docx",
    getImage: function(tagValue) {
        const imgPath = path.resolve(tagValue);
        if (fs.existsSync(imgPath)) {
            return fs.readFileSync(imgPath);
        }
        console.warn(`[Aviso] Imagem não encontrada: ${imgPath}`);
        return Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=", "base64");
    },
    getSize: function(img, tagValue, tagName) {
        try {
            // Lemos a imagem com o image-size
            const dimensions = sizeOf(img);
            
            // Retornamos exatamente a largura e altura originais! Sem cortes.
            return [dimensions.width, dimensions.height];
        } catch (e) {
            console.warn(`[Aviso] Falha ao ler dimensões da imagem. Usando fallback.`);
            return [600, 400]; 
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

    const buf = doc.getZip().generate({ 
        type: "nodebuffer", 
        compression: "DEFLATE" 
    });
    
    fs.writeFileSync(path.resolve(outputPath), buf);
    console.log("SUCCESS");

} catch (error) {
    console.error("ERROR:", error.message);
    if (error.properties && error.properties.errors) {
        console.error("Detalhes do erro do Docxtemplater:", error.properties.errors);
    }
    process.exit(1);
}