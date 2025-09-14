```dataviewjs

const folder = dv.current().file.folder;
let container = this.container;

dv.header(1, "## 💥 Vulnerabilidades Encontradas");
dv.table(
  ["Host", "IP", "CVSS", "Severidade", "Tipo"],
  dv.pages(`"${folder}"`)
    .where(p =>
      p.tipo === "vulnerabilidade" &&
      p.Tipo && p.Tipo.trim() !== ""
    )
    .sort(p => p.CVSS ?? 0, 'desc')
    .map(p => {
      const alvoFolder = p.file.path.split("/").slice(0, -2).join("/");
      const dashboardFile = `Dashboard_${p.targetName}.md`;
      return [
        dv.fileLink(`${alvoFolder}/${dashboardFile}`, false, p.targetName),
        p.t_IP,
        p.CVSS,
        p.Severidade,
        `[[${p.file.name}|${p.Tipo ?? "Vulnerabilidade"}]]`
      ];
    })
);

dv.header(1, "## 🌐 Endpoints Encontrados nos Alvos");
// Construir lista de endpoints (normalizados) e renderizar dentro de um bloco foldável
const targets = dv.pages(`"${folder}"`).where(p => p.tipo === "target");
let allEndpoints = new Map();
for (let target of targets) {
  const targetPath = target.file.path.split("/").slice(0, -1).join("/");
  const httpxPath = `${targetPath}/httpx.md`;
  const httpxFile = app.vault.getAbstractFileByPath(httpxPath);
  if (!httpxFile) continue;
  const raw = await app.vault.read(httpxFile);
  const lines = raw.split("\n").filter(l => l.startsWith("|") && !l.includes("---"));
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

    // Remove :80 e :443 de URLs padrão
    url = url.replace(/^http:\/\/([^\/:]+):80\b/, "http://$1");
    url = url.replace(/^https:\/\/([^\/:]+):443\b/, "https://$1");

    // Remove trailing slash, se houver (mas não da raiz do protocolo)
    url = url.replace(/\/$/, "");

    // Deduplica pelo valor da URL final normalizada
    if (!allEndpoints.has(url)) {
      allEndpoints.set(url, title);
    }
  }
}

let detailsMd = "<details><summary>↕️ Clique para expandir</summary>\n\n";

if (allEndpoints.size > 0) {
  Array.from(allEndpoints.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .forEach(([url, title]) => {
      detailsMd += `- [${url}](${url}) — **${title}**\n`;
    });

} else {
  detailsMd += "⚠️ Nenhum endpoint relevante encontrado nos alvos.\n";
}

detailsMd += "\n</details>";

dv.paragraph(detailsMd);

// Tabela de Portas e Serviços Enumerados
dv.header(1, "## 🖥️ Portas e Serviços Enumerados");
dv.table(
  ["Host", "IP", "Portas"],
  dv.pages(`"${folder}"`)
    .where(p => p.tipo === "target" && p.t_openPorts)
    .map(p => {
      const dashFile = `Dashboard_${p.targetName ?? p.file.name}`;
      return [
        `[[${dashFile}|${p.targetName ?? p.file.name}]]`,
        p.t_IP,
        p.t_openPorts.join(", ")
      ];
    })
);

```