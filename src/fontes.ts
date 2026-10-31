import { ehRce, expandirExploits, lerRegistroCve, parteLocal, type ParteCve, type Registro } from "./registro";
import type { Hoje, Item, Pacote, Sinais } from "./tipos";

const BASE = import.meta.env.BASE_URL;
const CVE_API = "https://cveawg.mitre.org/api/cve/";
const OSV_API = "https://api.osv.dev/v1";
const SIMULTANEOS = 8;
const LOTE_OSV = 500;
const TEMPO_LIMITE = 20000;

const caixas = new Map<string, Promise<Record<string, Registro>>>();

function caixa(ano: string, grupo: string): Promise<Record<string, Registro>> {
  const chave = `${ano}/${grupo}`;
  let p = caixas.get(chave);
  if (!p) {
    p = fetch(`${BASE}dados/c/${chave}.json`)
      .then((r) => (r.ok ? r.json() : {}))
      .catch(() => ({}));
    caixas.set(chave, p);
  }
  return p;
}

async function registroLocal(id: string): Promise<Registro> {
  const m = /^CVE-(\d{4})-(\d+)$/.exec(id);
  if (!m) return {};
  return (await caixa(m[1], m[2].slice(-2).padStart(2, "0")))[m[2]] ?? {};
}

export function hoje(): Promise<Hoje | null> {
  return fetch(`${BASE}dados/hoje.json`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
}

async function registroCve(id: string): Promise<ParteCve> {
  try {
    const r = await fetch(CVE_API + id, { signal: AbortSignal.timeout(TEMPO_LIMITE) });
    if (r.status === 404) return { estado: "nao_encontrado" };
    if (!r.ok) return { estado: "sem_consulta" };
    return lerRegistroCve(await r.json());
  } catch {
    return { estado: "sem_consulta" };
  }
}

const complementos = new Map<string, Promise<ParteCve>>();

// Descrição e referências ficam fora dos arquivos do site: vêm do registro, sob demanda.
export function complementoCve(id: string): Promise<ParteCve> {
  let p = complementos.get(id);
  if (!p) {
    p = registroCve(id);
    complementos.set(id, p);
  }
  return p;
}

const sinaisCache = new Map<string, Promise<Sinais>>();

export function consultarCve(id: string): Promise<Sinais> {
  let p = sinaisCache.get(id);
  if (!p) {
    p = registroLocal(id).then(async (l) => {
      // Sem registro local, o CVE pode ser mais novo que a base do dia.
      const c = l.s !== undefined ? parteLocal(l) : await complementoCve(id);
      return {
        id, ...c, kev: l.k, epss: l.e, percentil: l.p,
        // Metasploit, Nuclei e Exploit-DB estão nos dados do dia, mesmo para CVE novo.
        exploits: l.s !== undefined ? c.exploits : [...expandirExploits(l.l), ...(c.exploits ?? [])],
        titulo: c.titulo ?? l.k?.nome,
        descricao: c.descricao ?? l.k?.descricao,
        produto: c.produto ?? (l.k ? `${l.k.fornecedor} ${l.k.produto}` : undefined),
      };
    });
    sinaisCache.set(id, p);
  }
  return p;
}

export async function emParalelo<E, S>(lista: E[], f: (e: E) => Promise<S>, progresso?: (feitos: number) => void): Promise<S[]> {
  const saida = new Array<S>(lista.length);
  let proximo = 0;
  let feitos = 0;
  const trabalhador = async () => {
    while (proximo < lista.length) {
      const i = proximo++;
      saida[i] = await f(lista[i]);
      progresso?.(++feitos);
    }
  };
  await Promise.all(Array.from({ length: Math.min(SIMULTANEOS, lista.length) }, trabalhador));
  return saida;
}

interface Osv {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { fixed?: string }[] }[];
  }[];
  references?: { url: string }[];
}

async function postar(corpo: unknown): Promise<{ results: { vulns?: { id: string }[]; next_page_token?: string }[] }> {
  const r = await fetch(`${OSV_API}/querybatch`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(corpo), signal: AbortSignal.timeout(TEMPO_LIMITE * 3),
  });
  if (!r.ok) throw new Error(`OSV respondeu ${r.status}`);
  return r.json();
}

// Devolve, para cada pacote, os IDs de vulnerabilidade daquela versão.
async function idsPorPacote(pacotes: Pacote[]): Promise<string[][]> {
  const saida: string[][] = pacotes.map(() => []);
  for (let i = 0; i < pacotes.length; i += LOTE_OSV) {
    const lote = pacotes.slice(i, i + LOTE_OSV);
    let pendentes = lote.map((p, j) => ({ indice: i + j, consulta: { package: { name: p.nome, ecosystem: p.ecossistema }, version: p.versao } as Record<string, unknown> }));
    while (pendentes.length) {
      const { results } = await postar({ queries: pendentes.map((p) => p.consulta) });
      const seguintes: typeof pendentes = [];
      results.forEach((r, j) => {
        const p = pendentes[j];
        saida[p.indice].push(...(r.vulns ?? []).map((v) => v.id));
        if (r.next_page_token) seguintes.push({ indice: p.indice, consulta: { ...p.consulta, page_token: r.next_page_token } });
      });
      pendentes = seguintes;
    }
  }
  return saida;
}

const FAIXAS: Record<string, [number, string]> = {
  CRITICAL: [9.5, "crítica"], HIGH: [8, "alta"], MODERATE: [5, "média"], MEDIUM: [5, "média"], LOW: [2, "baixa"],
};

export function sinaisDeOsv(o: Osv): Sinais {
  const vetor = o.severity?.find((s) => s.type.startsWith("CVSS"))?.score;
  const faixa = FAIXAS[(o.database_specific?.severity ?? "").toUpperCase()];
  return {
    id: o.id, estado: "publicado", titulo: o.summary, descricao: o.details, publicado: o.published,
    cvss: faixa ? { nota: faixa[0], vetor, aproximada: true, rotulo: faixa[1] } : undefined,
    malicioso: o.id.startsWith("MAL-") || o.database_specific?.cwe_ids?.includes("CWE-506"),
    rce: ehRce(`${o.summary ?? ""} ${o.details ?? ""}`, o.database_specific?.cwe_ids ?? []),
    referencias: o.references?.map((r) => r.url).slice(0, 4),
  };
}

function corrigidaEm(o: Osv, p: Pacote): string | undefined {
  const a = o.affected?.find((x) => x.package?.name === p.nome);
  for (const r of a?.ranges ?? []) {
    const fixed = r.events?.find((e) => e.fixed)?.fixed;
    if (fixed) return fixed;
  }
  return undefined;
}

const osvCache = new Map<string, Promise<Osv>>();

function detalheOsv(id: string): Promise<Osv> {
  let p = osvCache.get(id);
  if (!p) {
    p = fetch(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(TEMPO_LIMITE) }).then((r) => {
      if (!r.ok) throw new Error(`OSV respondeu ${r.status}`);
      return r.json();
    });
    osvCache.set(id, p);
  }
  return p;
}

export async function consultarPacotes(pacotes: Pacote[], progresso: (etapa: string) => void): Promise<Item[]> {
  progresso(`Perguntando sobre ${pacotes.length} pacotes`);
  const ids = await idsPorPacote(pacotes);
  const pares = pacotes.flatMap((pacote, i) => ids[i].map((id) => ({ pacote, id })));
  const total = pares.length;
  progresso(`Conferindo ${total} vulnerabilidades`);
  const itens = await emParalelo(pares, async ({ pacote, id }): Promise<Item> => {
    const o = await detalheOsv(id);
    const base = sinaisDeOsv(o);
    const cve = id.startsWith("CVE-") ? id : o.aliases?.find((a) => a.startsWith("CVE-"));
    const corrigeEm = corrigidaEm(o, pacote);
    if (!cve) return { sinais: base, pacote, corrigeEm };
    const c = await consultarCve(cve);
    return {
      pacote, corrigeEm,
      sinais: {
        ...c, estado: c.estado === "nao_encontrado" || c.estado === "sem_consulta" ? "publicado" : c.estado,
        malicioso: base.malicioso, cvss: c.cvss ?? base.cvss, rce: c.rce || base.rce,
        titulo: base.titulo ?? c.titulo, descricao: c.descricao ?? base.descricao,
        publicado: c.publicado ?? base.publicado, referencias: c.referencias ?? base.referencias,
      },
    };
  }, (f) => progresso(`Conferindo ${f} de ${total} vulnerabilidades`));
  // O mesmo problema costuma vir com dois IDs (GHSA e PYSEC, por exemplo).
  const vistos = new Set<string>();
  return itens.filter((it) => {
    const chave = `${it.pacote?.nome}|${it.pacote?.versao}|${it.sinais.id}`;
    if (vistos.has(chave)) return false;
    vistos.add(chave);
    return true;
  });
}
