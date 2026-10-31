// Leitura do registro de CVE, usada pelo navegador e pelo pipeline diário.
import type { Cvss, Estado, Exploit, Kev, Sinais } from "./tipos";

interface Metrica {
  cvssV4_0?: { baseScore: number; vectorString: string };
  cvssV3_1?: { baseScore: number; vectorString: string };
  cvssV3_0?: { baseScore: number; vectorString: string };
  cvssV2_0?: { baseScore: number; vectorString: string };
  other?: { type?: string; content?: { options?: Record<string, string>[] } };
}

interface Conteiner {
  title?: string;
  descriptions?: { lang?: string; value: string }[];
  affected?: { vendor?: string; product?: string }[];
  metrics?: Metrica[];
  references?: { url: string; tags?: string[] }[];
  problemTypes?: { descriptions?: { cweId?: string }[] }[];
}

const RCE_TEXTO = /remote code execution|\bRCE\b|arbitrary (code|commands?) (execution|to be executed)|execut\w* arbitrary (code|commands?)|command injection|code injection|remote command execution/i;
const RCE_CWE = new Set(["CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-502", "CWE-917", "CWE-1336"]);
const MAX_EXPLOITS_REGISTRO = 3;

export function ehRce(texto: string | undefined, cwes: (string | undefined)[]): boolean {
  return RCE_TEXTO.test(texto ?? "") || cwes.some((c) => c !== undefined && RCE_CWE.has(c));
}

export interface ParteCve {
  estado: Estado;
  titulo?: string;
  descricao?: string;
  produto?: string;
  publicado?: string;
  cvss?: Cvss;
  exploracao?: Sinais["exploracao"];
  automatizavel?: boolean;
  referencias?: string[];
  rce?: boolean;
  exploits?: Exploit[];
}

export function lerRegistroCve(j: {
  cveMetadata?: { state?: string; datePublished?: string };
  containers?: { cna?: Conteiner; adp?: Conteiner[] };
}): ParteCve {
  if (j.cveMetadata?.state === "REJECTED") return { estado: "rejeitado" };
  const cna = j.containers?.cna ?? {};
  const todos = [cna, ...(j.containers?.adp ?? [])];
  const metricas = todos.flatMap((c) => c.metrics ?? []);

  let cvss: Cvss | undefined;
  for (const versao of ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"] as const) {
    const m = metricas.find((x) => x[versao])?.[versao];
    if (m) { cvss = { nota: m.baseScore, vetor: m.vectorString }; break; }
  }

  let exploracao: Sinais["exploracao"];
  let automatizavel: boolean | undefined;
  for (const m of metricas) {
    if (m.other?.type !== "ssvc") continue;
    for (const o of m.other.content?.options ?? []) {
      if (o.Exploitation) exploracao = o.Exploitation.toLowerCase() as Sinais["exploracao"];
      if (o.Automatable) automatizavel = o.Automatable.toLowerCase() === "yes";
    }
  }

  const afetado = cna.affected?.find((a) => a.product && a.product !== "n/a");
  const descricoes = cna.descriptions ?? [];
  const descricao = (descricoes.find((d) => d.lang?.startsWith("en")) ?? descricoes[0])?.value;
  const cwes = todos.flatMap((c) => c.problemTypes ?? []).flatMap((p) => p.descriptions ?? []).map((d) => d.cweId);
  const linksExploit = new Set(todos.flatMap((c) => c.references ?? [])
    .filter((r) => /^https?:\/\//.test(r.url) && r.tags?.some((t) => /exploit/i.test(t)))
    .map((r) => r.url));
  const url = cna.references?.map((r) => r.url).filter((u) => /^https?:\/\//.test(u)).slice(0, 4);
  return {
    estado: "publicado",
    titulo: cna.title,
    descricao,
    produto: afetado ? [afetado.vendor, afetado.product].filter((x) => x && x !== "n/a").join(" ") : undefined,
    publicado: j.cveMetadata?.datePublished,
    cvss, exploracao, automatizavel, referencias: url,
    rce: ehRce(`${cna.title ?? ""} ${descricao ?? ""}`, cwes),
    exploits: [...linksExploit].slice(0, MAX_EXPLOITS_REGISTRO).map((u) => ({ fonte: "registro" as const, url: u })),
  };
}

// Formato enxuto de cada CVE nos arquivos do site. "s" só existe para quem veio
// da base de CVEs: sem ele, o registro precisa ser consultado na hora.
export interface Registro {
  e?: number;
  p?: number;
  k?: Kev;
  s?: 0 | 1;
  t?: string;
  o?: string;
  d?: string;
  c?: number;
  v?: string;
  x?: "active" | "poc";
  a?: 1;
  r?: 1;
  // Exploits: fonte abreviada e caminho, para não repetir o endereço inteiro.
  l?: [string, string][];
}

const FONTES: Record<string, { fonte: Exploit["fonte"]; base: string }> = {
  m: { fonte: "metasploit", base: "https://github.com/rapid7/metasploit-framework/blob/master/" },
  a: { fonte: "metasploit_aux", base: "https://github.com/rapid7/metasploit-framework/blob/master/" },
  n: { fonte: "nuclei", base: "https://github.com/projectdiscovery/nuclei-templates/blob/main/" },
  e: { fonte: "exploitdb", base: "https://www.exploit-db.com/exploits/" },
  r: { fonte: "registro", base: "" },
};

export function expandirExploits(l: [string, string][] | undefined): Exploit[] {
  return (l ?? []).flatMap(([f, c]) => (FONTES[f] ? [{ fonte: FONTES[f].fonte, url: FONTES[f].base + c }] : []));
}

const LIMITE_TEXTO = 200;

export function compactar(p: ParteCve): Registro {
  if (p.estado === "rejeitado") return { s: 0 };
  const r: Registro = { s: 1 };
  if (p.titulo) r.t = p.titulo.slice(0, LIMITE_TEXTO);
  if (p.produto) r.o = p.produto.slice(0, LIMITE_TEXTO);
  if (p.publicado) r.d = p.publicado.slice(0, 10);
  if (p.cvss) { r.c = p.cvss.nota; r.v = p.cvss.vetor; }
  if (p.exploracao === "active" || p.exploracao === "poc") r.x = p.exploracao;
  if (p.automatizavel) r.a = 1;
  if (p.rce) r.r = 1;
  if (p.exploits?.length) r.l = p.exploits.map((e) => ["r", e.url]);
  return r;
}

export function parteLocal(r: Registro): ParteCve {
  if (r.s === 0) return { estado: "rejeitado" };
  return {
    estado: "publicado", titulo: r.t, produto: r.o, publicado: r.d,
    cvss: r.c !== undefined ? { nota: r.c, vetor: r.v } : undefined,
    exploracao: r.x, automatizavel: r.a === 1, rce: r.r === 1,
    exploits: expandirExploits(r.l),
  };
}
