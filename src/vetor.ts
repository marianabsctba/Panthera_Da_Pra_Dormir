// Traduz o vetor CVSS para português e para a vida real.

export interface LinhaVetor {
  metrica: string;
  valor: string;
  traducao: string;
}

const IMPACTO: Record<string, string> = {
  H: "Total. Leva tudo.",
  L: "Parcial. Leva um pouco.",
  N: "Nenhum. Aqui não encosta.",
};

const METRICAS: Record<string, { nome: string; valores: Record<string, string> }> = {
  AV: {
    nome: "De onde ataca",
    valores: {
      N: "Da internet. Do sofá de casa, de pijama.",
      A: "Da mesma rede. Precisa estar no seu Wi-Fi ou na sua VLAN.",
      L: "De dentro da máquina. Já precisa ter um pé lá.",
      P: "Com a mão no equipamento. Boa sorte com o crachá.",
    },
  },
  AC: {
    nome: "Dificuldade",
    valores: {
      L: "Baixa. Funciona sempre, sem depender de sorte.",
      H: "Alta. Depende de condições específicas ou de insistência.",
    },
  },
  AT: {
    nome: "Pré-requisitos do alvo",
    valores: {
      N: "Nenhum. Qualquer instalação serve.",
      P: "Precisa de uma condição específica no alvo.",
    },
  },
  PR: {
    nome: "Login necessário",
    valores: {
      N: "Nenhum. Entra sem bater.",
      L: "Conta comum. Aquela do estagiário de 2019 que ninguém desativou.",
      H: "Conta de admin. Se já tem isso, o problema é outro.",
    },
  },
  UI: {
    nome: "Precisa de alguém clicar?",
    valores: {
      N: "Não. Ninguém precisa fazer nada de errado.",
      R: "Sim. Alguém precisa clicar, e alguém sempre clica.",
      P: "Sim, de forma passiva. Basta a pessoa abrir ou visualizar.",
      A: "Sim, de forma ativa. A pessoa precisa colaborar bastante.",
    },
  },
  S: {
    nome: "Sai do quintal?",
    valores: {
      U: "Não. O estrago fica no componente vulnerável.",
      C: "Sim. Pula do componente vulnerável para outros sistemas.",
    },
  },
  C: { nome: "Confidencialidade", valores: IMPACTO },
  I: { nome: "Integridade", valores: IMPACTO },
  A: { nome: "Disponibilidade", valores: IMPACTO },
  VC: { nome: "Confidencialidade", valores: IMPACTO },
  VI: { nome: "Integridade", valores: IMPACTO },
  VA: { nome: "Disponibilidade", valores: IMPACTO },
  SC: { nome: "Confidencialidade dos vizinhos", valores: IMPACTO },
  SI: { nome: "Integridade dos vizinhos", valores: IMPACTO },
  SA: { nome: "Disponibilidade dos vizinhos", valores: IMPACTO },
};

export function partesVetor(vetor?: string): Record<string, string> {
  const partes: Record<string, string> = {};
  for (const p of (vetor ?? "").split("/")) {
    const [k, v] = p.split(":");
    if (k && v && k !== "CVSS") partes[k] = v;
  }
  return partes;
}

export function explicarVetor(vetor?: string): LinhaVetor[] {
  const linhas: LinhaVetor[] = [];
  for (const [k, v] of Object.entries(partesVetor(vetor))) {
    const m = METRICAS[k];
    const traducao = m?.valores[v];
    if (m && traducao) linhas.push({ metrica: m.nome, valor: `${k}:${v}`, traducao });
  }
  return linhas;
}
