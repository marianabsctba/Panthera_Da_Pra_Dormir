export type Nivel = "acorda" | "cedo" | "olho" | "dorme" | "incerto" | "inexistente";
export type Exposicao = "internet" | "interna" | "nao_sei";
export type Estado = "publicado" | "rejeitado" | "nao_encontrado" | "sem_consulta";

export interface Kev {
  fornecedor: string;
  produto: string;
  nome: string;
  desde: string;
  prazo: string;
  ransomware: boolean;
  acao: string;
  descricao: string;
}

export interface Cvss {
  nota: number;
  vetor?: string;
  // Quando a fonte só dá a faixa (Alta, Crítica), a nota é aproximada e não aparece.
  aproximada?: boolean;
  rotulo?: string;
}

export interface Sinais {
  id: string;
  estado: Estado;
  titulo?: string;
  descricao?: string;
  produto?: string;
  publicado?: string;
  kev?: Kev;
  epss?: number;
  percentil?: number;
  cvss?: Cvss;
  exploracao?: "active" | "poc" | "none";
  automatizavel?: boolean;
  referencias?: string[];
  malicioso?: boolean;
}

export interface Pacote {
  nome: string;
  versao: string;
  ecossistema: "npm" | "PyPI" | "Go";
  soDev: boolean;
}

export interface LeituraPacotes {
  formato: string;
  pacotes: Pacote[];
  // Pacotes de registro privado ou sem versão fixa: não são consultados.
  privados: number;
  semVersao: number;
}

export interface Item {
  sinais: Sinais;
  pacote?: Pacote;
  corrigeEm?: string;
}

export interface Motivo {
  tipo: "ruim" | "atencao" | "bom" | "info";
  titulo: string;
  texto: string;
}

export interface Veredito {
  nivel: Nivel;
  motivos: Motivo[];
}

export interface Hoje {
  dataEpss: string;
  versaoKev: string;
  versaoCve: string;
  totalCve: number;
  totalKev: number;
  totalEpss: number;
  recentes: { id: string; nome: string; desde: string; ransomware: boolean }[];
  subindo: { id: string; epss: number; antes: number; nome: string | null }[];
}
