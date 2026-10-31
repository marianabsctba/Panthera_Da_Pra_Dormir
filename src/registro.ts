// Leitura do registro de CVE, usada pelo navegador e pelo pipeline diário.
import type { Cvss, Estado, Kev, Sinais } from "./tipos";

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
  references?: { url: string }[];
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
  const url = cna.references?.map((r) => r.url).filter((u) => /^https?:\/\//.test(u)).slice(0, 4);
  return {
    estado: "publicado",
    titulo: cna.title,
    descricao: (descricoes.find((d) => d.lang?.startsWith("en")) ?? descricoes[0])?.value,
    produto: afetado ? [afetado.vendor, afetado.product].filter((x) => x && x !== "n/a").join(" ") : undefined,
    publicado: j.cveMetadata?.datePublished,
    cvss, exploracao, automatizavel, referencias: url,
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
  return r;
}

export function parteLocal(r: Registro): ParteCve {
  if (r.s === 0) return { estado: "rejeitado" };
  return {
    estado: "publicado", titulo: r.t, produto: r.o, publicado: r.d,
    cvss: r.c !== undefined ? { nota: r.c, vetor: r.v } : undefined,
    exploracao: r.x, automatizavel: r.a === 1,
  };
}
