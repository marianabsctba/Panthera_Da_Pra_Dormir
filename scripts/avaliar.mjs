// Confere a regra de decisão contra a base inteira, não contra um CVE de cada vez.
// Roda depois de scripts/dados.mjs: se um princípio quebrar, nada é publicado.
// Com --historico, repete a medida do KEV usando o EPSS de antes de cada falha
// entrar na lista, o que tira o viés de um EPSS que já viu o ataque.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { buscarEm } from "../src/busca.ts";
import { parteLocal } from "../src/registro.ts";
import { decidir } from "../src/veredito.ts";

const PASTA = join(dirname(fileURLToPath(import.meta.url)), "..", "public", "dados", "c");
const agora = new Date(JSON.parse(readFileSync(join(PASTA, "..", "hoje.json"), "utf8")).dataEpss);

// Alerta demais vira ruído, e aí nada é urgente.
const MAX_ALERTA = 0.3;
const MIN_KEV_SEM_SINAL = 0.7;

// Casos reais que já discutimos. Cada um diz os níveis aceitáveis.
const CASOS = {
  "CVE-2021-44228": ["acorda"],
  "CVE-2014-0160": ["acorda"],
  "CVE-2026-39842": ["cedo", "acorda"],
  "CVE-2025-3691": ["olho"],
  // Sem nota no registro: não dá para mandar dormir no escuro.
  "CVE-2021-1028": ["incerto"],
};

const ALERTA = new Set(["acorda", "cedo"]);
const violacoes = {};
const exemplos = {};
function violou(nome, id) {
  violacoes[nome] = (violacoes[nome] ?? 0) + 1;
  (exemplos[nome] ??= []).length < 5 && exemplos[nome].push(id);
}

function sinais(id, r) {
  return { id, ...parteLocal(r), kev: r.k, epss: r.e, percentil: r.p };
}
// Esconde a confirmação de exploração: o resto da regra teria notado?
const semConfirmacao = (s) => ({ ...s, kev: undefined, exploracao: s.exploracao === "active" ? undefined : s.exploracao });

const total = {};
const recentes = { total: 0, alerta: 0 };
const kev = { total: 0, alerta: 0, kev2026: 0, alerta2026: 0, semExploit2026: 0 };
const casos = {};
const kev2026 = [];

for (const ano of readdirSync(PASTA)) {
  for (const arq of readdirSync(join(PASTA, ano))) {
    const caixa = JSON.parse(readFileSync(join(PASTA, ano, arq), "utf8"));
    for (const [num, r] of Object.entries(caixa)) {
      if (r.s === undefined) continue; // só no KEV ou no EPSS, fora da base de CVEs
      const id = `CVE-${ano}-${num}`;
      const s = sinais(id, r);
      if (s.estado === "rejeitado") continue;
      const nivel = decidir(s, "nao_sei", false, agora).nivel;
      total[nivel] = (total[nivel] ?? 0) + 1;

      const interna = decidir(s, "interna", true, agora).nivel;
      if (nivel === "dorme" && s.cvss === undefined) violou("sem nota virou dorme", id);
      if (nivel === "dorme" && s.rce) violou("execução de código virou dorme", id);
      if (interna === "dorme" && s.rce) violou("execução de código virou dorme depois dos ajustes", id);
      if (nivel === "dorme" && s.exploits?.length) violou("exploit conhecido virou dorme", id);
      if (s.exploits?.some((e) => e.fonte === "metasploit" || e.fonte === "nuclei") && !ALERTA.has(nivel) && nivel !== "incerto") violou("automação pública sem alerta", id);
      if (s.kev && !ALERTA.has(nivel)) violou("KEV sem alerta", id);
      if (s.cvss?.nota >= 9 && s.cvss.vetor?.includes("AV:N") && !s.cvss.vetor.includes("PR:H") && !ALERTA.has(nivel)) violou("crítico remoto sem alerta", id);

      if (ano >= "2025") {
        recentes.total++;
        if (ALERTA.has(nivel)) recentes.alerta++;
      }
      if (s.kev) {
        const oculto = decidir(semConfirmacao(s), "nao_sei", false, agora).nivel;
        kev.total++;
        if (ALERTA.has(oculto)) kev.alerta++;
        if (s.kev.desde >= "2026-01-01") {
          kev.kev2026++;
          if (ALERTA.has(oculto)) kev.alerta2026++;
          if (ALERTA.has(decidir({ ...semConfirmacao(s), exploits: undefined }, "nao_sei", false, agora).nivel)) kev.semExploit2026++;
          kev2026.push({ s, desde: s.kev.desde });
        }
      }
      if (CASOS[id]) casos[id] = nivel;
      // XSS marcado com CWE-94: não pode ganhar a etiqueta de execução de código.
      if (id === "CVE-2025-3688" && s.rce) violou("XSS marcado como execução de código", id);
    }
  }
}

const pct = (a, b) => `${((a / b) * 100).toFixed(1)}%`;
console.log("Níveis", total);
const tudo = Object.values(total).reduce((a, b) => a + b, 0);
const alerta = (total.acorda ?? 0) + (total.cedo ?? 0);
console.log(`Em alerta: ${alerta} de ${tudo} (${pct(alerta, tudo)}). CVEs de 2025 e 2026: ${pct(recentes.alerta, recentes.total)}`);
console.log(`KEV sem a confirmação: ${pct(kev.alerta, kev.total)}. Entradas de 2026: ${pct(kev.alerta2026, kev.kev2026)}, sem as fontes de exploit: ${pct(kev.semExploit2026, kev.kev2026)}`);

for (const [id, aceitos] of Object.entries(CASOS)) {
  console.log(`${id}: ${casos[id]}`);
  if (!aceitos.includes(casos[id])) violou(`caso real fora do esperado (${aceitos.join(" ou ")})`, id);
}
// A busca precisa achar o que qualquer pessoa procuraria.
const BUSCAS = {
  log4j: "2021-44228",
  log4shell: "2021-44228",
  heartbleed: "2014-0160",
  shellshock: "2014-6271",
  "dirty cow": "2016-5195",
  "JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP": "2021-44228",
};
const lerBalde = async (nome) => {
  try { return JSON.parse(readFileSync(join(PASTA, "..", "b", `${nome}.json`), "utf8")); } catch { return {}; }
};
for (const [texto, esperado] of Object.entries(BUSCAS)) {
  const r = await buscarEm(texto, lerBalde);
  const lugar = r.ids.indexOf(esperado);
  console.log(`Busca "${texto.slice(0, 40)}": ${r.total} resultados, CVE-${esperado} na posição ${lugar + 1}`);
  if (lugar < 0 || lugar >= 30) violou("busca não achou caso conhecido", texto.slice(0, 40));
}
if ((await buscarEm("xyzzyqqvw", lerBalde)).ids.length) violou("busca inventou resultado", "xyzzyqqvw");

if (alerta / tudo > MAX_ALERTA) violou("alerta demais", `${pct(alerta, tudo)}`);
if (kev.alerta / kev.total < MIN_KEV_SEM_SINAL) violou("KEV escapando sem a confirmação", pct(kev.alerta, kev.total));

if (process.argv.includes("--historico")) {
  // Um arquivo por semana basta: o EPSS de até 14 dias antes da entrada no KEV.
  const semanal = new Map();
  async function baixarEpss(data) {
    for (let tentativa = 1; ; tentativa++) {
      try {
        const r = await fetch(`https://epss.empiricalsecurity.com/epss_scores-${data}.csv.gz`, { signal: AbortSignal.timeout(120000) });
        if (!r.ok) throw new Error(`EPSS de ${data} respondeu ${r.status}`);
        return r;
      } catch (e) {
        if (tentativa >= 5) throw e;
        await new Promise((ok) => setTimeout(ok, tentativa * 3000));
      }
    }
  }
  async function epssEm(data) {
    const d = new Date(`${data}T00:00:00Z`);
    d.setUTCDate(d.getUTCDate() - 7 - (d.getUTCDay() % 7));
    const chave = d.toISOString().slice(0, 10);
    if (!semanal.has(chave)) {
      const r = await baixarEpss(chave);
      const mapa = new Map();
      for (const l of gunzipSync(Buffer.from(await r.arrayBuffer())).toString("utf8").split("\n").slice(2)) {
        const [c, e] = l.split(",");
        if (c && e) mapa.set(c, Number(e));
      }
      semanal.set(chave, mapa);
    }
    return semanal.get(chave);
  }
  let comEpss = 0, alertaEpoca = 0, alertaEpocaSemExploit = 0, alertaEpssSo = 0;
  const niveis = {};
  for (const { s, desde } of kev2026) {
    const mapa = await epssEm(desde);
    const antes = { ...semConfirmacao(s), epss: mapa.get(s.id) };
    if (antes.epss !== undefined) comEpss++;
    const n = decidir(antes, "nao_sei", false, new Date(desde)).nivel;
    niveis[n] = (niveis[n] ?? 0) + 1;
    if (ALERTA.has(n)) alertaEpoca++;
    if (ALERTA.has(decidir({ ...antes, exploits: undefined }, "nao_sei", false, new Date(desde)).nivel)) alertaEpocaSemExploit++;
    if ((antes.epss ?? 0) >= 0.05) alertaEpssSo++;
  }
  console.log(`\nKEV de 2026 com o EPSS da época (${kev2026.length} falhas, ${comEpss} com EPSS):`, niveis);
  console.log(`Alerta: ${pct(alertaEpoca, kev2026.length)}. Sem as fontes de exploit: ${pct(alertaEpocaSemExploit, kev2026.length)}. Só EPSS de 5% ou mais: ${pct(alertaEpssSo, kev2026.length)}`);
}

const nomes = Object.keys(violacoes);
if (nomes.length) {
  console.error("\nPrincípios quebrados:");
  for (const n of nomes) console.error(`- ${n}: ${violacoes[n]} (${exemplos[n].join(", ")})`);
  process.exit(1);
}
console.log("\nTodos os princípios valem na base inteira.");
