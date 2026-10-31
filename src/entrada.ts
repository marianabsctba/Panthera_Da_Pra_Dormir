import type { LeituraPacotes, Pacote } from "./tipos";

export const LIMITE_CVES = 200;

export function extrairCves(texto: string): string[] {
  const achados = texto.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
  return [...new Set(achados.map((c) => c.toUpperCase()))];
}

interface EntradaV2 {
  version?: string;
  resolved?: string;
  dev?: boolean;
  link?: boolean;
}

interface EntradaV1 extends EntradaV2 {
  dependencies?: Record<string, EntradaV1>;
}

function publicoNpm(resolved: string | undefined): boolean {
  if (!resolved) return true;
  try {
    return new URL(resolved).hostname === "registry.npmjs.org";
  } catch {
    return false;
  }
}

function unicos(pacotes: Pacote[]): Pacote[] {
  const mapa = new Map<string, Pacote>();
  for (const p of pacotes) {
    const chave = `${p.ecossistema}|${p.nome}|${p.versao}`;
    const antes = mapa.get(chave);
    // Se alguma cópia vai para produção, o pacote não é só de desenvolvimento.
    if (!antes) mapa.set(chave, { ...p });
    else if (!p.soDev) antes.soDev = false;
  }
  return [...mapa.values()];
}

function lerPackageLock(j: { packages?: Record<string, EntradaV2>; dependencies?: Record<string, EntradaV1> }): LeituraPacotes {
  const pacotes: Pacote[] = [];
  let privados = 0;
  let semVersao = 0;
  const somar = (nome: string, e: EntradaV2) => {
    if (e.link) return;
    if (!e.version || !publicoNpm(e.resolved) || /^[a-z+]+:/i.test(e.version)) {
      if (e.version) privados++; else semVersao++;
      return;
    }
    pacotes.push({ nome, versao: e.version, ecossistema: "npm", soDev: e.dev === true });
  };
  if (j.packages) {
    for (const [caminho, e] of Object.entries(j.packages)) {
      if (!caminho) continue;
      const i = caminho.lastIndexOf("node_modules/");
      if (i < 0) continue; // pacote local do workspace
      somar(caminho.slice(i + "node_modules/".length), e);
    }
  } else if (j.dependencies) {
    const andar = (deps: Record<string, EntradaV1>) => {
      for (const [nome, e] of Object.entries(deps)) {
        somar(nome, e);
        if (e.dependencies) andar(e.dependencies);
      }
    };
    andar(j.dependencies);
  }
  return { formato: "package-lock.json", pacotes: unicos(pacotes), privados, semVersao };
}

function lerRequirements(texto: string): LeituraPacotes | null {
  const pacotes: Pacote[] = [];
  let semVersao = 0;
  for (const bruta of texto.split(/\r?\n/)) {
    const l = bruta.replace(/\s+#.*$/, "").trim();
    if (!l || l.startsWith("#") || l.startsWith("-") || l.startsWith("--")) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)(\s*;.*)?(\s*\\)?$/.exec(l);
    if (m) pacotes.push({ nome: m[1], versao: m[3], ecossistema: "PyPI", soDev: false });
    else if (/^[A-Za-z0-9][A-Za-z0-9._\[\], -]*([<>~!=]=?.*)?$/.test(l)) semVersao++;
    else return null;
  }
  if (!pacotes.length) return null;
  return { formato: "requirements.txt", pacotes: unicos(pacotes), privados: 0, semVersao };
}

function lerGoMod(texto: string): LeituraPacotes | null {
  if (!/^module\s+\S+/m.test(texto)) return null;
  const pacotes: Pacote[] = [];
  let dentro = false;
  for (const bruta of texto.split(/\r?\n/)) {
    const l = bruta.trim();
    if (/^require\s*\($/.test(l)) { dentro = true; continue; }
    if (l === ")") { dentro = false; continue; }
    const m = /^(?:require\s+)?([^\s]+\.[^\s]+)\s+(v[^\s]+)/.exec(l);
    if (m && (dentro || l.startsWith("require"))) pacotes.push({ nome: m[1], versao: m[2], ecossistema: "Go", soDev: false });
  }
  return { formato: "go.mod", pacotes: unicos(pacotes), privados: 0, semVersao: 0 };
}

export function lerPacotes(texto: string): LeituraPacotes | null {
  const limpo = texto.trim();
  if (limpo.startsWith("{")) {
    try {
      const j = JSON.parse(limpo);
      if (j && typeof j === "object" && "lockfileVersion" in j) return lerPackageLock(j);
    } catch { /* não é JSON */ }
    return null;
  }
  return lerGoMod(limpo) ?? lerRequirements(limpo);
}
