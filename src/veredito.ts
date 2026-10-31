import type { Exposicao, Nivel, Sinais, Veredito, Motivo } from "./tipos";
import { partesVetor } from "./vetor";

// Limites de decisão. É um critério nosso, explicado na tela "Como a gente decide".
export const EPSS_CERTO = 0.9;
export const EPSS_ALTO = 0.5;
export const EPSS_MEDIO = 0.1;
export const EPSS_BAIXO = 0.01;
export const CVSS_CRITICO = 9;
export const CVSS_ALTO = 7;
// O EPSS demora para reagir: CVE recente ainda não tem histórico de exploração.
export const DIAS_RECENTE = 14;
const DIAS_KEV_ANTIGO = 365;

const ESCADA: Nivel[] = ["dorme", "olho", "cedo", "acorda"];

export function porcentagem(x: number): string {
  const p = x * 100;
  if (p >= 99.5) return "acima de 99%";
  return `${p < 1 ? p.toFixed(2) : p < 10 ? p.toFixed(1) : p.toFixed(0)}%`.replace(".", ",");
}

function dias(publicado: string | undefined, agora: Date): number | undefined {
  if (!publicado) return undefined;
  const t = Date.parse(publicado);
  return Number.isNaN(t) ? undefined : (agora.getTime() - t) / 86400000;
}

function dataBr(iso: string): string {
  const [a, m, d] = iso.slice(0, 10).split("-");
  return `${d}/${m}/${a}`;
}

export function decidir(s: Sinais, exposicao: Exposicao, soDev = false, agora = new Date()): Veredito {
  const motivos: Motivo[] = [];

  if (s.malicioso) {
    motivos.push({
      tipo: "ruim", titulo: "Pacote malicioso",
      texto: "Isso não é falha de programação: alguém publicou esse pacote para roubar ou invadir. Não basta atualizar. Trate a máquina e os segredos que passaram por ela como comprometidos.",
    });
    return { nivel: "acorda", motivos };
  }
  if (s.estado === "rejeitado") {
    motivos.push({ tipo: "info", titulo: "CVE rejeitado", texto: "O próprio programa CVE rejeitou esse registro: duplicado, engano ou alarme falso. Alguém vai te mandar esse número mesmo assim." });
    return { nivel: "inexistente", motivos };
  }
  if (s.estado === "nao_encontrado" && !s.kev && s.epss === undefined) {
    motivos.push({ tipo: "info", titulo: "Não existe registro público", texto: "Esse número não aparece em nenhuma fonte. Pode ser erro de digitação, ou um CVE reservado que ainda não foi publicado." });
    return { nivel: "inexistente", motivos };
  }

  const v = partesVetor(s.cvss?.vetor);
  const remoto = v.AV ? v.AV === "N" || v.AV === "A" : undefined;
  const local = v.AV === "L" || v.AV === "P";
  const idade = dias(s.publicado, agora);
  const recente = idade !== undefined && idade <= DIAS_RECENTE;
  const nota = s.cvss?.nota;
  const epss = s.epss;
  const semLogin = v.PR === "N" && v.UI === "N";

  if (s.kev) {
    motivos.push({
      tipo: "ruim", titulo: "Já estão explorando",
      texto: `Está no KEV desde ${dataBr(s.kev.desde)}, o catálogo da CISA de falhas com exploração confirmada. Aqui ninguém está especulando: já tem gente apanhando.`,
    });
    if (s.kev.ransomware) {
      motivos.push({ tipo: "ruim", titulo: "Usada em ransomware", texto: "Essa falha já apareceu em campanha de ransomware. A rede inteira entra na conta, inclusive o que não está exposto." });
    }
    const naLista = dias(s.kev.desde, agora);
    if (naLista !== undefined && naLista > DIAS_KEV_ANTIGO) {
      motivos.push({ tipo: "info", titulo: "Não é novidade", texto: "Essa falha é conhecida há tempo. Se já foi corrigida aí, pode voltar para a cama. O veredito vale para quem ainda tem isso rodando, e sempre tem alguém." });
    }
  } else if (s.exploracao === "active") {
    motivos.push({ tipo: "ruim", titulo: "Exploração ativa", texto: "A CISA registrou exploração em andamento, mesmo fora do catálogo KEV." });
  } else {
    motivos.push({ tipo: "bom", titulo: "Fora do KEV", texto: "Não há exploração confirmada no catálogo da CISA. Isso não prova que ninguém explora, só que ninguém confirmou." });
  }

  if (epss !== undefined) {
    const faixa = epss >= EPSS_ALTO ? "ruim" : epss >= EPSS_MEDIO ? "atencao" : "bom";
    motivos.push({
      tipo: faixa, titulo: `EPSS ${porcentagem(epss)}`,
      texto: `Chance estimada de exploração nos próximos 30 dias. ${epss >= EPSS_CERTO ? "A moeda já caiu, e caiu do lado errado." : faixa === "ruim" ? "Cara ou coroa, com a moeda torcendo contra você." : faixa === "atencao" ? "Não é a maioria, mas já é bem acima do normal." : "Baixa. A maioria das falhas nunca é explorada, e essa parece ser uma delas."}`,
    });
  } else {
    motivos.push({ tipo: "info", titulo: "Sem EPSS", texto: "Ainda não há estimativa de exploração para esse CVE." });
  }

  if (nota !== undefined) {
    const faixa = s.cvss?.aproximada ? `Gravidade ${s.cvss.rotulo}` : `CVSS ${String(nota).replace(".", ",")}`;
    motivos.push({
      tipo: nota >= CVSS_CRITICO ? "atencao" : "info", titulo: faixa,
      texto: nota >= CVSS_CRITICO
        ? "Nota assustadora, e é ela que vai para a manchete. Mas o CVSS mede o tamanho do estrago, não a chance de acontecer."
        : "O CVSS mede o tamanho do estrago, não a chance de acontecer.",
    });
  }
  if (s.exploracao === "poc") {
    motivos.push({ tipo: "atencao", titulo: "Tem exploit público", texto: `Existe prova de conceito pública${s.automatizavel ? ", e o ataque dá para automatizar. Um script e a internet inteira entra na fila." : ". Ainda precisa de alguém disposto a adaptar."}` });
  }

  let n: number;
  if (s.kev || s.exploracao === "active") n = 3;
  else if (epss !== undefined && epss >= EPSS_ALTO) n = remoto === false ? 2 : 3;
  else if ((epss !== undefined && epss >= EPSS_MEDIO) || (s.exploracao === "poc" && s.automatizavel)) n = 2;
  else if (nota !== undefined && nota >= CVSS_CRITICO && remoto && semLogin && recente) {
    n = 2;
    motivos.push({ tipo: "atencao", titulo: "Recém-publicado", texto: "Crítico, remoto, sem login e com menos de duas semanas. O EPSS ainda não teve tempo de reagir, então não dá para confiar no número baixo." });
  } else if ((nota !== undefined && nota >= CVSS_ALTO) || (epss !== undefined && epss >= EPSS_BAIXO) || s.exploracao === "poc") n = 1;
  else if (nota === undefined && (epss === undefined || recente)) {
    if (s.estado === "sem_consulta") motivos.push({ tipo: "info", titulo: "Consulta incompleta", texto: "Não conseguimos falar com o registro de CVEs agora, então falta a gravidade. Tente de novo em alguns minutos." });
    return { nivel: "incerto", motivos };
  } else n = 0;

  const ransomware = s.kev?.ransomware === true;
  if (n > 0 && !ransomware) {
    if (local && n === 3) {
      n = 2;
      motivos.push({ tipo: "bom", titulo: "Precisa estar lá dentro", texto: "O ataque parte de dentro da máquina. Normalmente é o segundo passo de uma invasão, não o primeiro." });
    } else if (!local && exposicao === "interna") {
      n -= 1;
      motivos.push({ tipo: "bom", titulo: "Não está na internet", texto: "Você disse que fica só na rede interna, então baixamos um nível. Vale enquanto a sua rede for mesmo tão segmentada quanto o desenho diz." });
    }
  }
  if (exposicao === "internet" && remoto && n >= 1) {
    motivos.push({ tipo: "atencao", titulo: "Exposto na internet", texto: "O ataque é remoto e você disse que está exposto. Aqui a prioridade não abaixa." });
  }
  if (soDev && n > 0 && !ransomware) {
    n -= 1;
    motivos.push({ tipo: "bom", titulo: "Só em desenvolvimento", texto: "Essa dependência não vai para produção, então baixamos um nível. A máquina de quem desenvolve continua sendo um alvo ótimo." });
  }

  return { nivel: ESCADA[n], motivos };
}

export const ORDEM: Record<Nivel, number> = { acorda: 0, cedo: 1, incerto: 2, olho: 3, dorme: 4, inexistente: 5 };
