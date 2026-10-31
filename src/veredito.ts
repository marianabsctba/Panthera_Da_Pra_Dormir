import type { Exposicao, Nivel, Sinais, Veredito, Motivo } from "./tipos";
import { partesVetor } from "./vetor";

// Limites de decisão. É um critério nosso, explicado na tela "Como a gente decide"
// e conferido contra a base inteira por scripts/avaliar.mjs. Três princípios:
// 1. Falta de dado nunca tranquiliza: sem nota não é nota baixa, e não achar exploit
//    não quer dizer que não exista.
// 2. Sinal grave põe um piso: execução de código ou exploit conhecido nunca dá "dorme",
//    nem depois dos ajustes de exposição.
// 3. Nem todo exploit pesa igual: módulo pronto para usar vale mais que um link citado.
export const EPSS_CERTO = 0.9;
export const EPSS_ALTO = 0.5;
export const EPSS_MEDIO = 0.05;
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
  const semAdmin = v.PR !== "H";
  const idade = dias(s.publicado, agora);
  const recente = idade !== undefined && idade <= DIAS_RECENTE;
  const nota = s.cvss?.nota;
  const epss = s.epss;
  const exploits = s.exploits ?? [];
  const moduloPronto = exploits.some((e) => e.fonte === "metasploit");
  const armado = moduloPronto || exploits.some((e) => e.fonte === "nuclei" || e.fonte === "metasploit_aux");
  const temExploit = exploits.length > 0 || s.exploracao === "poc";
  const critico = nota !== undefined && nota >= CVSS_CRITICO;

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
    motivos.push({ tipo: "info", titulo: "Fora do KEV", texto: "Ninguém confirmou exploração no catálogo da CISA. Isso não prova que ninguém explora, só que ninguém confirmou." });
  }

  if (s.rce) {
    motivos.push({
      tipo: "atencao", titulo: "Execução de código",
      texto: "A descrição ou o tipo da falha indica que dá para rodar código ou comandos no alvo. Esse é o estrago que todo mundo teme, seja qual for a nota. Por isso, aqui o veredito nunca é \"dorme\".",
    });
  }

  if (moduloPronto) {
    motivos.push({ tipo: "ruim", titulo: "Módulo pronto no Metasploit", texto: "Quem quiser atacar não precisa entender a falha: é escolher o alvo e apertar o botão." });
  } else if (armado) {
    motivos.push({ tipo: "atencao", titulo: "Já tem automação pública", texto: "Existe modelo público para procurar essa falha em massa. Quem faz varredura na internet já tem isso pronto." });
  } else if (temExploit) {
    motivos.push({ tipo: "atencao", titulo: "Tem exploit público", texto: `Tem exploit citado em fonte pública${s.automatizavel ? ", e a CISA avalia que o ataque dá para automatizar." : ". Ainda precisa de alguém disposto a adaptar, mas já não dá para contar com a dificuldade."}` });
  }

  if (epss !== undefined) {
    const faixa = epss >= EPSS_ALTO ? "ruim" : epss >= EPSS_MEDIO ? "atencao" : "bom";
    // O EPSS olha a internet inteira: produto de nicho pontua baixo mesmo com falha grave.
    const graveMesmoAssim = faixa === "bom" && (critico || s.rce || armado);
    motivos.push({
      tipo: graveMesmoAssim ? "atencao" : faixa, titulo: `EPSS ${porcentagem(epss)}`,
      texto: `Chance estimada de exploração nos próximos 30 dias. ${epss >= EPSS_CERTO ? "A moeda já caiu, e caiu do lado errado." : faixa === "ruim" ? "Cara ou coroa, com a moeda torcendo contra você." : faixa === "atencao" ? "Não é a maioria, mas já é bem acima do normal." : graveMesmoAssim ? "Parece pouco, mas o EPSS olha a internet inteira. Atacante em massa não liga para produto de nicho, e quem mira especificamente em você não entra nessa conta. Se você usa isso, não se console com esse número." : "Baixa, e isso ajuda, mas é só uma estimativa."}`,
    });
  } else {
    motivos.push({ tipo: "info", titulo: "Sem EPSS", texto: "Ainda não há estimativa de exploração para esse CVE." });
  }

  if (nota !== undefined) {
    const faixa = s.cvss?.aproximada ? `Gravidade ${s.cvss.rotulo}` : `CVSS ${String(nota).replace(".", ",")}`;
    motivos.push({
      tipo: critico ? "atencao" : "info", titulo: faixa,
      texto: critico
        ? "Nota assustadora, e é ela que vai para a manchete. Mas o CVSS mede o tamanho do estrago, não a chance de acontecer."
        : "O CVSS mede o tamanho do estrago, não a chance de acontecer.",
    });
  } else {
    motivos.push({ tipo: "atencao", titulo: "Sem nota", texto: "Ninguém deu nota para essa falha no registro. Falta de nota não é nota baixa, então a gente não manda dormir no escuro." });
  }

  let n: number;
  if (s.kev || s.exploracao === "active") n = 3;
  else if (epss !== undefined && epss >= EPSS_ALTO) n = remoto === false ? 2 : 3;
  else if (moduloPronto && remoto !== false && semAdmin) n = 3;
  else if (armado || (epss !== undefined && epss >= EPSS_MEDIO) || (s.exploracao === "poc" && s.automatizavel)) n = 2;
  else if (critico && remoto !== false && semAdmin) {
    // Falha crítica já explorada costuma ter EPSS baixo: ele reage depois do ataque.
    n = 2;
    motivos.push({
      tipo: "atencao", titulo: temExploit ? "Crítico e com exploit na mão" : "Crítico e remoto",
      texto: temExploit
        ? "Nota crítica, ataque remoto, sem precisar de admin e com exploit público. O trabalho difícil alguém já fez. Falta só alguém se interessar pelo seu servidor."
        : `Nota crítica, ataque remoto e sem precisar de admin. ${recente ? "Foi publicado há menos de duas semanas, então o EPSS ainda nem teve tempo de reagir." : "Muita falha assim já estava sendo explorada enquanto o EPSS ainda dizia que era pouco provável."} Não é para hoje de madrugada, mas também não é para a fila.`,
    });
  } else if (s.rce && remoto !== false && semAdmin && (nota === undefined || nota >= CVSS_ALTO)) {
    n = 2;
    motivos.push({ tipo: "atencao", titulo: "Código remoto sem admin", texto: "Rodar código de longe sem precisar de conta de admin é o tipo de falha que vira invasão. Não é para hoje de madrugada, mas também não é para a fila." });
  } else if ((nota !== undefined && nota >= CVSS_ALTO) || (epss !== undefined && epss >= EPSS_BAIXO) || temExploit || s.rce) n = 1;
  else if (nota === undefined) {
    if (s.estado === "sem_consulta") motivos.push({ tipo: "info", titulo: "Consulta incompleta", texto: "Não conseguimos falar com o registro de CVEs agora, então falta a gravidade. Tente de novo em alguns minutos." });
    return { nivel: "incerto", motivos };
  } else n = 0;

  // Piso: a exposição pode baixar a prioridade, mas não apagar um sinal grave.
  const piso = s.rce || temExploit || critico ? 1 : 0;
  const ransomware = s.kev?.ransomware === true;
  if (n > 0 && !ransomware) {
    if (local && n === 3) {
      n = 2;
      motivos.push({ tipo: "bom", titulo: "Precisa estar lá dentro", texto: "O ataque parte de dentro da máquina. Normalmente é o segundo passo de uma invasão, não o primeiro." });
    } else if (!local && exposicao === "interna" && n > piso) {
      n -= 1;
      motivos.push({ tipo: "bom", titulo: "Não está na internet", texto: "Você disse que fica só na rede interna, então baixamos um nível. Vale enquanto a sua rede for mesmo tão segmentada quanto o desenho diz." });
    }
  }
  if (exposicao === "internet" && remoto && n >= 1) {
    motivos.push({ tipo: "atencao", titulo: "Exposto na internet", texto: "O ataque é remoto e você disse que está exposto. Aqui a prioridade não abaixa." });
  }
  if (soDev && n > piso && !ransomware) {
    n -= 1;
    motivos.push({ tipo: "bom", titulo: "Só em desenvolvimento", texto: "Essa dependência não vai para produção, então baixamos um nível. A máquina de quem desenvolve continua sendo um alvo ótimo." });
  }

  return { nivel: ESCADA[n], motivos };
}

export const ORDEM: Record<Nivel, number> = { acorda: 0, cedo: 1, incerto: 2, olho: 3, dorme: 4, inexistente: 5 };
