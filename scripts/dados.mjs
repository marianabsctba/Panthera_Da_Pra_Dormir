// Monta os dados estáticos do site a partir das fontes públicas (KEV, EPSS, a
// base inteira de CVEs e os índices de exploit).
// Roda todo dia no GitHub Actions. Se um feed vier estranho, falha sem publicar
// e o site continua com os dados do dia anterior.
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import yauzl from "yauzl";
import { baldeDe, palavras, TETO_PALAVRA } from "../src/busca.ts";
import { compactar, lerRegistroCve } from "../src/registro.ts";

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), "..");
const SAIDA = join(RAIZ, "public", "dados");
const KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_HOJE = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const EPSS_DIA = (d) => `https://epss.empiricalsecurity.com/epss_scores-${d}.csv.gz`;
const BASE_CVE = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest";
const TEMPO_BASE = 900000;
const EXPLOIT_DB = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
const METASPLOIT = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json";
const NUCLEI = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json";

// Abaixo disso o feed veio cortado ou mudou de formato.
const MIN_KEV = 1000;
const MIN_EPSS = 200000;
const MIN_CVE = 300000;
const MAX_CVE_COM_ERRO = 100;
const TENTATIVAS = 4;
const MIN_EXPLOIT_DB = 3000;
const MIN_METASPLOIT = 1500;
const MIN_NUCLEI = 2000;
const MAX_LINKS_POR_FONTE = 3;
// Só conta como "subiu de repente" quem chegou a uma chance relevante.
const EPSS_MIN_SUBINDO = 0.1;

async function baixar(url, tempo = 120000) {
  for (let tentativa = 1; ; tentativa++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(tempo) });
      if (!r.ok) throw new Error(`${url} respondeu ${r.status}`);
      return r;
    } catch (e) {
      if (tentativa >= TENTATIVAS) throw e;
      console.log(`Falhou ${url}, tentando de novo: ${e.cause?.code ?? e.message}`);
      await new Promise((ok) => setTimeout(ok, tentativa * 5000));
    }
  }
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

function abrirZip(caminho) {
  return new Promise((ok, erro) => yauzl.open(caminho, { lazyEntries: true }, (e, z) => (e ? erro(e) : ok(z))));
}

function abrirEntrada(zip, entrada) {
  return new Promise((ok, erro) => zip.openReadStream(entrada, (e, s) => (e ? erro(e) : ok(s))));
}

function percorrerZip(zip, f) {
  return new Promise((ok, erro) => {
    zip.on("entry", (entrada) => {
      f(entrada).then(() => zip.readEntry()).catch((e) => { zip.close(); erro(e); });
    });
    zip.on("end", ok);
    zip.on("error", erro);
    zip.readEntry();
  });
}

// A base vem como um zip dentro de outro, com um JSON por CVE.
async function lerBaseCve(porCve) {
  const pasta = await mkdtemp(join(tmpdir(), "dormir-"));
  try {
    const release = await (await baixar(BASE_CVE)).json();
    const ativo = release.assets?.find((a) => /_all_CVEs_at_midnight\.zip\.zip$/.test(a.name));
    if (!ativo) throw new Error("base de CVEs sem o arquivo esperado");
    const r = await baixar(ativo.browser_download_url, TEMPO_BASE);
    const fora = join(pasta, "fora.zip");
    await pipeline(Readable.fromWeb(r.body), createWriteStream(fora));

    const dentro = join(pasta, "cves.zip");
    const zipFora = await abrirZip(fora);
    await percorrerZip(zipFora, async (e) => {
      if (e.fileName.endsWith(".zip")) await pipeline(await abrirEntrada(zipFora, e), createWriteStream(dentro));
    });

    let total = 0;
    let erros = 0;
    const zip = await abrirZip(dentro);
    await percorrerZip(zip, async (e) => {
      if (!/CVE-\d{4}-\d+\.json$/.test(e.fileName)) return;
      const partes = [];
      for await (const p of await abrirEntrada(zip, e)) partes.push(p);
      try {
        const j = JSON.parse(Buffer.concat(partes).toString("utf8"));
        const estado = j.cveMetadata?.state;
        if (estado !== "PUBLISHED" && estado !== "REJECTED") return;
        porCve(j.cveMetadata.cveId, lerRegistroCve(j));
        total++;
      } catch {
        erros++;
      }
    });
    if (erros > MAX_CVE_COM_ERRO) throw new Error(`${erros} CVEs ilegíveis na base`);
    return { total, versao: release.tag_name };
  } finally {
    await rm(pasta, { recursive: true, force: true });
  }
}

function linhasCsv(texto) {
  const linhas = [];
  let campo = "";
  let linha = [];
  let aspas = false;
  for (let i = 0; i < texto.length; i++) {
    const c = texto[i];
    if (aspas) {
      if (c === '"' && texto[i + 1] === '"') { campo += '"'; i++; }
      else if (c === '"') aspas = false;
      else campo += c;
    } else if (c === '"') aspas = true;
    else if (c === ",") { linha.push(campo); campo = ""; }
    else if (c === "\n") { linha.push(campo); linhas.push(linha); linha = []; campo = ""; }
    else if (c !== "\r") campo += c;
  }
  return linhas;
}

// Cada índice devolve pares [CVE, fonte abreviada, caminho do link].
async function lerExploitDb() {
  const [cabecalho, ...linhas] = linhasCsv(await (await baixar(EXPLOIT_DB)).text());
  const id = cabecalho.indexOf("id");
  const codes = cabecalho.indexOf("codes");
  if (id < 0 || codes < 0) throw new Error("Exploit-DB em formato inesperado");
  return linhas.flatMap((l) => (l[codes] ?? "").split(";").filter((c) => /^CVE-\d{4}-\d+$/.test(c)).map((c) => [c, "e", l[id]]));
}

async function lerMetasploit() {
  const modulos = Object.values(await (await baixar(METASPLOIT)).json());
  return modulos.filter((m) => m.type === "exploit" || m.type === "auxiliary").flatMap((m) =>
    (m.references ?? []).map((r) => /^CVE-(\d{4}-\d+)$/.exec(r)).filter(Boolean)
      .map((c) => [`CVE-${c[1]}`, m.type === "exploit" ? "m" : "a", m.path.replace(/^\//, "")]));
}

async function lerNuclei() {
  const texto = await (await baixar(NUCLEI)).text();
  return texto.split("\n").filter(Boolean).flatMap((l) => {
    const j = JSON.parse(l);
    return /^CVE-\d{4}-\d+$/.test(j.ID) && j.file_path ? [[j.ID, "n", j.file_path]] : [];
  });
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

// Índice de palavras: cada palavra aponta para os CVEs em que aparece.
const indice = new Map();
const cvesDoIndice = [];
const base = await lerBaseCve((cve, parte) => {
  const r = registro(cve);
  if (!r) return;
  Object.assign(r, compactar(parte));
  if (parte.estado !== "publicado") return;
  const n = cvesDoIndice.push(cve) - 1;
  const texto = `${parte.titulo ?? ""} ${parte.produto ?? ""} ${parte.descricao ?? ""} ${r.k?.nome ?? ""}${parte.rce ? " rce" : ""}`;
  for (const p of palavras(texto)) {
    const lista = indice.get(p);
    if (lista) lista.push(n);
    else indice.set(p, [n]);
  }
});
if (base.total < MIN_CVE) throw new Error("base de CVEs veio pequena demais");

// Fonte fora do ar não pode virar "não tem exploit": sem ela, nada é publicado.
for (const [nome, ler, minimo] of [["Exploit-DB", lerExploitDb, MIN_EXPLOIT_DB], ["Metasploit", lerMetasploit, MIN_METASPLOIT], ["Nuclei", lerNuclei, MIN_NUCLEI]]) {
  const pares = await ler();
  if (pares.length < minimo) throw new Error(`${nome} veio pequeno demais: ${pares.length}`);
  for (const [cve, fonte, caminho] of pares) {
    const r = registro(cve);
    if (!r) continue;
    r.l ??= [];
    if (r.l.filter(([f]) => f === fonte).length < MAX_LINKS_POR_FONTE) r.l.unshift([fonte, caminho]);
  }
  console.log(`${nome}: ${pares.length} ligações com CVE`);
}

await rm(SAIDA, { recursive: true, force: true });
for (const [chave, conteudo] of caixas) {
  const arquivo = join(SAIDA, "c", `${chave}.json`);
  await mkdir(dirname(arquivo), { recursive: true });
  await writeFile(arquivo, JSON.stringify(conteudo));
}

// Falha já explorada vem antes, depois quem tem mais chance de ser explorada.
const importancia = cvesDoIndice.map((cve) => {
  const r = registro(cve);
  return (r.k ? 2 : 0) + (r.e ?? 0);
});
const baldes = new Map();
for (const [p, lista] of indice) {
  lista.sort((a, b) => importancia[b] - importancia[a]);
  const nome = baldeDe(p);
  if (!baldes.has(nome)) baldes.set(nome, {});
  baldes.get(nome)[p] = [lista.length, ...lista.slice(0, TETO_PALAVRA).map((n) => cvesDoIndice[n].slice(4))];
}
await mkdir(join(SAIDA, "b"), { recursive: true });
for (const [nome, conteudo] of baldes) await writeFile(join(SAIDA, "b", `${nome}.json`), JSON.stringify(conteudo));

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
for (const s of topo) {
  const r = registro(s.id);
  s.nome = r?.t ?? r?.o ?? null;
}

await writeFile(join(SAIDA, "hoje.json"), JSON.stringify({
  dataEpss: epss.data, versaoKev: kev.catalogVersion, versaoCve: base.versao, totalCve: base.total, totalKev: kev.vulnerabilities.length, totalEpss: epss.notas.size, recentes, subindo: topo,
}));

console.log(`CVE ${base.total}, KEV ${kev.vulnerabilities.length}, EPSS ${epss.notas.size} (${epss.data}), ${caixas.size} arquivos, ${indice.size} palavras`);
