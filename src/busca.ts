// Busca por palavra, usada pelo pipeline (que monta o índice) e pelo navegador.
// O índice fica dividido em baldes: cada palavra baixa só um arquivo pequeno.

export const BALDES = 2048;
// Palavra comum demais guarda só os CVEs mais importantes e serve só para ordenar.
export const TETO_PALAVRA = 5000;
const MAX_PALAVRAS = 12;
// Até aqui é uma busca, em que todas as palavras contam. Acima, é um trecho colado.
const MAX_BUSCA_CURTA = 4;

const VAZIAS = new Set([
  "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "has", "have", "had", "can", "could", "may", "might", "via", "into", "not", "when", "which",
  "allows", "allow", "attacker", "attackers", "vulnerability", "vulnerabilities", "issue", "version", "versions", "before", "after", "prior", "using", "use", "used", "cve",
  "para", "com", "uma", "que", "dos", "das", "nos", "nas", "por", "sem", "falha", "falhas", "vulnerabilidade", "vulnerabilidades",
]);

// As descrições oficiais são em inglês: quem busca em português ainda acha.
const TRADUCOES: Record<string, string> = {
  injecao: "injection", execucao: "execution", codigo: "code", remota: "remote", remoto: "remote", senha: "password", senhas: "password",
  autenticacao: "authentication", roteador: "router", roteadores: "router", negacao: "denial", servico: "service", vazamento: "leak",
  arquivo: "file", arquivos: "file", usuario: "user", usuarios: "user", impressora: "printer", impressoras: "printer", camera: "camera", cameras: "camera",
  navegador: "browser", servidor: "server", servidores: "server", banco: "database",
};

// Nome famoso nem sempre aparece no registro do CVE.
export const APELIDOS: Record<string, string[]> = {
  log4shell: ["2021-44228"], heartbleed: ["2014-0160"], shellshock: ["2014-6271"], eternalblue: ["2017-0144"], wannacry: ["2017-0144"],
  bluekeep: ["2019-0708"], proxylogon: ["2021-26855"], proxyshell: ["2021-34473"], zerologon: ["2020-1472"], printnightmare: ["2021-34527"],
  spectre: ["2017-5753"], meltdown: ["2017-5754"], dirtycow: ["2016-5195"], dirtypipe: ["2022-0847"], follina: ["2022-30190"],
  spring4shell: ["2022-22965"], citrixbleed: ["2023-4966"], poodle: ["2014-3566"], krack: ["2017-13077"], regresshion: ["2024-6387"],
  ghostcat: ["2020-1938"], pwnkit: ["2021-4034"], baronsamedit: ["2021-3156"], moveit: ["2023-34362"],
};

export function palavras(texto: string): string[] {
  const limpo = texto.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
  const achadas = (limpo.match(/[a-z0-9][a-z0-9._-]*[a-z0-9]/g) ?? []).flatMap((x) => [x, ...x.split(/[._-]+/)]);
  return [...new Set(achadas.filter((x) => x.length >= 3 && x.length <= 40 && !VAZIAS.has(x) && !/^\d+$/.test(x)))];
}

export function baldeDe(palavra: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < palavra.length; i++) {
    h ^= palavra.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ((h >>> 0) % BALDES).toString(16).padStart(3, "0");
}

// Cada palavra guarda [total real, ...ids mais importantes primeiro].
export type Balde = Record<string, (number | string)[]>;

export interface ResultadoBusca {
  ids: string[];
  total: number;
  // Palavras que não aparecem em nenhum CVE: a busca segue sem elas, e a tela avisa.
  ignoradas: string[];
  querRce: boolean;
}

export async function buscarEm(texto: string, lerBalde: (nome: string) => Promise<Balde>, limite = 60): Promise<ResultadoBusca> {
  const originais = palavras(texto);
  const pedidas = [...new Set(originais.map((p) => TRADUCOES[p] ?? p))].slice(0, MAX_PALAVRAS);
  const colada = originais.join("");
  const diretos = [...new Set([...(APELIDOS[colada] ?? []), ...originais.flatMap((p) => APELIDOS[p] ?? [])])];

  const listas: { palavra: string; total: number; ids: string[] }[] = [];
  const ignoradas: string[] = [];
  for (const palavra of pedidas) {
    const achada = (await lerBalde(baldeDe(palavra)))[palavra];
    if (achada) listas.push({ palavra, total: achada[0] as number, ids: achada.slice(1) as string[] });
    else if (!APELIDOS[palavra]) ignoradas.push(palavra);
  }
  const querRce = pedidas.includes("rce");

  const acertos = new Map<string, number>();
  const posicao = new Map<string, number>();
  for (const l of listas) {
    l.ids.forEach((id, i) => {
      acertos.set(id, (acertos.get(id) ?? 0) + 1);
      posicao.set(id, Math.min(posicao.get(id) ?? Infinity, i));
    });
  }

  let candidatos: string[];
  if (pedidas.length > MAX_BUSCA_CURTA) {
    const minimo = Math.ceil(listas.length / 2);
    candidatos = [...acertos.keys()].filter((id) => acertos.get(id)! >= minimo);
  } else {
    // Só palavra com a lista completa pode excluir: a cortada deixaria CVE de fora.
    const completas = listas.filter((l) => l.total <= TETO_PALAVRA).map((l) => new Set(l.ids));
    if (completas.length) candidatos = [...completas[0]].filter((id) => completas.every((c) => c.has(id)));
    else {
      candidatos = [...acertos.keys()].filter((id) => acertos.get(id) === listas.length);
      if (!candidatos.length && listas.length) candidatos = [...listas].sort((a, b) => a.total - b.total)[0].ids;
    }
  }
  candidatos.sort((a, b) => acertos.get(b)! - acertos.get(a)! || posicao.get(a)! - posicao.get(b)!);

  const ids = [...new Set([...diretos, ...candidatos])];
  return { ids: ids.slice(0, limite), total: ids.length, ignoradas, querRce };
}
