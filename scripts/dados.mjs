// Monta os dados estáticos do site a partir dos feeds públicos (KEV e EPSS).
// Roda todo dia no GitHub Actions. Se um feed vier estranho, falha sem publicar
// e o site continua com os dados do dia anterior.
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), "..");
const SAIDA = join(RAIZ, "public", "dados");
const KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_HOJE = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const EPSS_DIA = (d) => `https://epss.empiricalsecurity.com/epss_scores-${d}.csv.gz`;
const CVE_API = (id) => `https://cveawg.mitre.org/api/cve/${id}`;

// Abaixo disso o feed veio cortado ou mudou de formato.
const MIN_KEV = 1000;
const MIN_EPSS = 200000;
// Só conta como "subiu de repente" quem chegou a uma chance relevante.
const EPSS_MIN_SUBINDO = 0.1;

async function baixar(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(120000) });
  if (!r.ok) throw new Error(`${url} respondeu ${r.status}`);
  return r;
}

async function lerEpss(url) {
  const r = await baixar(url);
  const texto = gunzipSync(Buffer.from(await r.arrayBuffer())).toString("utf8");
  const linhas = texto.split("\n");
  const data = /score_date:(\d{4}-\d{2}-\d{2})/.exec(linhas[0])?.[1];
  if (!data || linhas[1]?.trim() !== "cve,epss,percentile") throw new Error(`EPSS em formato inesperado: ${url}`);
  const notas = new Map();
  for (const l of linhas.slice(2)) {
    const [cve, e, p] = l.split(",");
    if (cve && e && p) notas.set(cve, [Number(e), Number(p)]);
  }
  return { data, notas };
}

function caixa(cve) {
  const [, ano, num] = /^CVE-(\d{4})-(\d+)$/.exec(cve) ?? [];
  if (!ano) return null;
  return { ano, grupo: num.slice(-2).padStart(2, "0"), num };
}

async function tituloDe(cve) {
  try {
    const j = await (await baixar(CVE_API(cve))).json();
    const cna = j.containers?.cna;
    const produto = cna?.affected?.find((a) => a.product && a.product !== "n/a")?.product;
    return cna?.title ?? produto ?? null;
  } catch {
    return null;
  }
}

const kev = await (await baixar(KEV)).json();
if (!Array.isArray(kev.vulnerabilities) || kev.vulnerabilities.length < MIN_KEV) throw new Error("KEV veio pequeno demais");

const epss = await lerEpss(EPSS_HOJE);
if (epss.notas.size < MIN_EPSS) throw new Error("EPSS veio pequeno demais");

const antes = new Date(`${epss.data}T00:00:00Z`);
antes.setUTCDate(antes.getUTCDate() - 7);
const epssAntes = await lerEpss(EPSS_DIA(antes.toISOString().slice(0, 10)));

// Cada CVE fica num arquivo por ano e dois últimos dígitos: o navegador baixa
// só alguns KB em vez dos feeds inteiros.
const caixas = new Map();
function registro(cve) {
  const c = caixa(cve);
  if (!c) return null;
  const chave = `${c.ano}/${c.grupo}`;
  if (!caixas.has(chave)) caixas.set(chave, {});
  return (caixas.get(chave)[c.num] ??= {});
}

for (const [cve, [e, p]] of epss.notas) {
  const r = registro(cve);
  if (r) { r.e = e; r.p = p; }
}
for (const v of kev.vulnerabilities) {
  const r = registro(v.cveID);
  if (r) {
    r.k = {
      fornecedor: v.vendorProject, produto: v.product, nome: v.vulnerabilityName, desde: v.dateAdded,
      prazo: v.dueDate, ransomware: v.knownRansomwareCampaignUse === "Known", acao: v.requiredAction, descricao: v.shortDescription,
    };
  }
}

await rm(SAIDA, { recursive: true, force: true });
for (const [chave, conteudo] of caixas) {
  const arquivo = join(SAIDA, "c", `${chave}.json`);
  await mkdir(dirname(arquivo), { recursive: true });
  await writeFile(arquivo, JSON.stringify(conteudo));
}

const naKev = new Set(kev.vulnerabilities.map((v) => v.cveID));
const recentes = [...kev.vulnerabilities]
  .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID))
  .slice(0, 6)
  .map((v) => ({ id: v.cveID, nome: `${v.vendorProject} ${v.product}`, desde: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === "Known" }));

const subindo = [];
for (const [cve, [e]] of epss.notas) {
  if (e < EPSS_MIN_SUBINDO || naKev.has(cve)) continue;
  const anterior = epssAntes.notas.get(cve)?.[0] ?? 0;
  if (e > anterior) subindo.push({ id: cve, epss: e, antes: anterior });
}
subindo.sort((a, b) => b.epss - b.antes - (a.epss - a.antes));
const topo = subindo.slice(0, 6);
for (const s of topo) s.nome = await tituloDe(s.id);

await writeFile(join(SAIDA, "hoje.json"), JSON.stringify({
  dataEpss: epss.data, versaoKev: kev.catalogVersion, totalKev: kev.vulnerabilities.length, totalEpss: epss.notas.size, recentes, subindo: topo,
}));

console.log(`KEV ${kev.vulnerabilities.length}, EPSS ${epss.notas.size} (${epss.data}), ${caixas.size} arquivos`);
