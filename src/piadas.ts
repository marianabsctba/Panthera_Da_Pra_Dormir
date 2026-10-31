import type { Nivel } from "./tipos";

export const TITULOS: Record<Nivel, string> = {
  acorda: "Acorda alguém.",
  cedo: "Dorme, mas põe o alarme.",
  olho: "Pode dormir. Corrige na semana.",
  dorme: "Dorme em paz.",
  incerto: "Ainda não dá para saber.",
  inexistente: "Esse CVE não existe.",
};

export const ROTULOS: Record<Nivel, string> = {
  acorda: "Acorda",
  cedo: "Alarme",
  olho: "Na semana",
  dorme: "Dorme",
  incerto: "Sem dados",
  inexistente: "Não existe",
};

const PIADAS: Record<Nivel, string[]> = {
  acorda: [
    "Liga para o plantão. Se o plantão for você, meus sentimentos.",
    "Não é simulação. Passa o café e abre a janela de mudança de emergência.",
    "Tem gente explorando isso agora, e essa gente não respeita o horário comercial.",
    "Hoje a reunião de alinhamento pode esperar. O atacante não vai alinhar nada com você.",
  ],
  cedo: [
    "Não precisa acordar ninguém, mas é o primeiro assunto de amanhã, antes do bom dia no grupo.",
    "Ainda não é incêndio. É cheiro de queimado.",
    "Dá para dormir, desde que o alarme não seja o de sempre com três sonecas.",
    "Amanhã cedo. E \"cedo\" não significa depois da daily.",
  ],
  olho: [
    "A manchete grita, os dados não. Entra na janela normal de correção.",
    "Fornecedor vai te ligar dizendo que é urgente. Ele também vende a solução.",
    "Vai para a fila. Só não deixa virar aquele ticket que faz aniversário.",
    "Nota alta, pressa baixa. Corrige com calma e com teste.",
  ],
  dorme: [
    "Boa noite. Se alguém te acordar por isso, manda este link.",
    "Pode desligar o celular. Tem falha bem pior na sua lista, mas não é essa.",
    "Nem o atacante está animado com essa.",
    "Entra no ciclo normal de atualização. O travesseiro te espera.",
  ],
  incerto: [
    "Faltam dados para um veredito honesto, e chute a gente deixa para o fornecedor.",
    "Ninguém sabe ainda. Quem disser que sabe está vendendo alguma coisa.",
  ],
  inexistente: [
    "Sabe o e-mail urgente que você recebeu? Pois é.",
    "Pode ser erro de digitação. Pode ser o gerente lendo número de cabeça.",
  ],
};

export function piada(nivel: Nivel, semente: string): string {
  let h = 0;
  for (const c of semente) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const lista = PIADAS[nivel];
  return lista[h % lista.length];
}

export const ACOES: Record<Nivel, string[]> = {
  acorda: [
    "Confirme se você usa o produto e a versão afetada.",
    "Aplique a correção agora. Se não der, isole da internet ou aplique a mitigação do fornecedor.",
    "Procure sinais de invasão nos logs. Corrigir não expulsa quem já entrou.",
  ],
  cedo: [
    "Veja amanhã cedo onde isso roda e o que está exposto.",
    "Agende a correção para os próximos dias, começando pelo que está na internet.",
    "Acompanhe: se entrar no KEV, o veredito muda para acordar alguém.",
  ],
  olho: [
    "Coloque na janela normal de correção.",
    "Volte aqui se surgir exploit público ou se o EPSS disparar.",
  ],
  dorme: ["Corrija na próxima atualização de rotina."],
  incerto: [
    "Veja se você usa o produto afetado e leia o aviso do fornecedor.",
    "Consulte de novo em um ou dois dias, quando houver mais dados.",
  ],
  inexistente: ["Confira o número e peça a fonte para quem te mandou."],
};
