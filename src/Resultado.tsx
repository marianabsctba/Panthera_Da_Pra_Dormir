import { useEffect, useState } from "react";
import { AlarmClock, ArrowLeft, BedDouble, Check, CircleAlert, CircleCheck, CircleHelp, Copy, ExternalLink, Eye, Ghost, Info, Send, Siren, TriangleAlert, type LucideIcon } from "lucide-react";
import { complementoCve } from "./fontes";
import { ACOES, ROTULOS, TITULOS, piada } from "./piadas";
import type { ParteCve } from "./registro";
import { ORDEM, decidir } from "./veredito";
import { explicarVetor } from "./vetor";
import type { Exploit, Exposicao, Item, LeituraPacotes, Motivo, Nivel, Sinais, Veredito } from "./tipos";

const ICONES: Record<Nivel, LucideIcon> = {
  acorda: Siren, cedo: AlarmClock, olho: Eye, dorme: BedDouble, incerto: CircleHelp, inexistente: Ghost,
};
const ICONES_MOTIVO: Record<Motivo["tipo"], LucideIcon> = {
  ruim: CircleAlert, atencao: TriangleAlert, bom: CircleCheck, info: Info,
};

export interface Exposta {
  valor: Exposicao;
  mudar: (e: Exposicao) => void;
}

function vereditoDe(item: Item, e: Exposicao): Veredito {
  return decidir(item.sinais, e, item.pacote?.soDev);
}

const NOMES_FONTE: Record<Exploit["fonte"], string> = {
  metasploit: "Módulo de ataque no Metasploit",
  metasploit_aux: "Módulo auxiliar no Metasploit",
  nuclei: "Modelo de varredura no Nuclei",
  exploitdb: "Exploit-DB",
  registro: "Citado no registro do CVE",
};

function Exploits({ s }: { s: Sinais }) {
  const lista = s.exploits ?? [];
  return (
    <>
      <h2>Exploit público</h2>
      {lista.length > 0 ? (
        <>
          <div className="aviso-exploit" role="note">
            <strong>Olhe, não execute.</strong>
            <ul>
              <li>Exploit público pode vir com malware de brinde. Não rode na sua máquina nem na da empresa: use só um laboratório isolado.</li>
              <li>Teste apenas em sistema seu ou com autorização por escrito. Invadir dispositivo alheio é crime (art. 154-A do Código Penal).</li>
              <li>A gente não testou nenhum desses links. Eles servem para entender o ataque e testar a sua detecção.</li>
            </ul>
          </div>
          <ul className="exploits">
            {lista.map((e) => (
              <li key={e.url}>
                <a href={e.url} target="_blank" rel="noreferrer noopener nofollow">
                  <span>{NOMES_FONTE[e.fonte]}</span>
                  <code>{e.url.replace(/^https?:\/\//, "")}</code>
                  <ExternalLink size={16} aria-hidden />
                </a>
              </li>
            ))}
          </ul>
        </>
      ) : s.exploracao === "poc" ? (
        <p>A CISA registra exploit público, mas não achei o link nas fontes que consulto.</p>
      ) : (
        <p>Não achei exploit em Metasploit, Nuclei, Exploit-DB e no registro do CVE. Isso não quer dizer que não exista: boa parte das falhas já exploradas não aparece em nenhuma dessas fontes.</p>
      )}
    </>
  );
}

function misturar(s: Sinais, extra: ParteCve | null): Sinais {
  if (extra?.estado !== "publicado") return s;
  return {
    ...s,
    rce: s.rce || extra.rce, exploits: s.exploits?.length ? s.exploits : extra.exploits,
    cvss: s.cvss ?? extra.cvss, exploracao: s.exploracao ?? extra.exploracao, automatizavel: s.automatizavel || extra.automatizavel,
    publicado: s.publicado ?? extra.publicado, titulo: s.titulo ?? extra.titulo, produto: s.produto ?? extra.produto,
    descricao: extra.descricao ?? s.descricao, referencias: extra.referencias ?? s.referencias,
  };
}

function Exposicao_({ exposta }: { exposta: Exposta }) {
  const opcoes: [Exposicao, string][] = [["internet", "Na internet"], ["interna", "Só na rede interna"], ["nao_sei", "Nem sei"]];
  return (
    <fieldset className="exposicao">
      <legend>Onde isso roda aí?</legend>
      <div>
        {opcoes.map(([v, r]) => (
          <button key={v} type="button" aria-pressed={exposta.valor === v} className={exposta.valor === v ? "ativo" : ""} onClick={() => exposta.mudar(v)}>{r}</button>
        ))}
      </div>
      {exposta.valor === "nao_sei" && <p className="dica">"Nem sei" conta como internet. Quem não sabe costuma descobrir pelo atacante.</p>}
    </fieldset>
  );
}

export function Detalhe({ item, exposta, voltar, rotuloVoltar }: { item: Item; exposta: Exposta; voltar: () => void; rotuloVoltar: string }) {
  const { pacote, corrigeEm } = item;
  const eCve = item.sinais.id.startsWith("CVE-");
  const [extra, setExtra] = useState<ParteCve | null>(null);
  const [buscando, setBuscando] = useState(false);
  const buscar = () => {
    if (!eCve || extra || buscando) return;
    setBuscando(true);
    void complementoCve(item.sinais.id).then(setExtra).finally(() => setBuscando(false));
  };
  // CVE ainda sem nota na base do dia: o registro pode já ter a nota.
  useEffect(() => {
    if (item.sinais.estado === "publicado" && !item.sinais.cvss) buscar();
  }, []);
  const s = misturar(item.sinais, extra);
  const v = vereditoDe({ ...item, sinais: s }, exposta.valor);
  const Icone = ICONES[v.nivel];
  const [copiado, setCopiado] = useState(false);
  const linhas = explicarVetor(s.cvss?.vetor);
  const fim = v.nivel === "inexistente";

  const copiar = async () => {
    const dados = [s.kev ? "no KEV" : null, s.epss !== undefined ? `EPSS ${(s.epss * 100).toFixed(1)}%` : null, s.cvss && !s.cvss.aproximada ? `CVSS ${s.cvss.nota}` : null].filter(Boolean).join(", ");
    const link = s.id.startsWith("CVE-") ? `${location.origin}${location.pathname}#${s.id}` : "";
    await navigator.clipboard.writeText(`${s.id}: ${TITULOS[v.nivel]} ${piada(v.nivel, s.id, s.cvss?.nota)}${dados ? ` (${dados})` : ""} ${link}`.trim());
    setCopiado(true);
    setTimeout(() => setCopiado(false), 2000);
  };

  return (
    <section className="resultado">
      <button className="voltar" onClick={voltar}><ArrowLeft size={18} aria-hidden /> {rotuloVoltar}</button>
      <div className={`veredito ${v.nivel}`}>
        <Icone size={56} aria-hidden />
        <p className="veredito-id">{s.id}{s.produto ? `, ${s.produto}` : ""}</p>
        {!s.produto && (s.titulo ?? s.resumo) && <p className="veredito-id">{s.titulo ?? s.resumo}</p>}
        <h1>{TITULOS[v.nivel]}</h1>
        <p>{piada(v.nivel, s.id, s.cvss?.nota)}</p>
      </div>

      {pacote && (
        <p className="pacote-linha">
          <strong>{pacote.nome}</strong> {pacote.versao}
          {corrigeEm && <>, corrigido em <strong>{corrigeEm}</strong></>}
          {pacote.soDev && <>, só em desenvolvimento</>}
        </p>
      )}

      {!fim && <Exposicao_ exposta={exposta} />}

      <h2>Por quê</h2>
      <ul className="achados">
        {v.motivos.map((m) => {
          const I = ICONES_MOTIVO[m.tipo];
          return (
            <li key={m.titulo} className={`achado ${m.tipo}`}>
              <span className="selo"><I size={22} aria-hidden /></span>
              <div><strong>{m.titulo}</strong><p>{m.texto}</p></div>
            </li>
          );
        })}
      </ul>

      <h2>O que fazer</h2>
      <ol className="passos">{ACOES[v.nivel].map((a) => <li key={a}>{a}</li>)}</ol>
      {s.kev && !fim && (
        <p className="dica prazo">
          {Date.parse(s.kev.prazo) < Date.now()
            ? `O prazo dos órgãos federais dos EUA para corrigir venceu em ${s.kev.prazo.split("-").reverse().join("/")}. Se o seu ainda não foi corrigido, o atraso já tem bastante companhia na internet.`
            : `Órgãos federais dos EUA têm até ${s.kev.prazo.split("-").reverse().join("/")} para corrigir. Esse prazo não vale para você, mas o atacante também não está esperando por ele.`}
        </p>
      )}

      {!fim && <Exploits s={s} />}

      {linhas.length > 0 && (
        <>
          <h2>A nota traduzida</h2>
          <p className="dica">Esse código esquisito ao lado da nota diz como o ataque funciona. Ler isso vale mais que ler o número.</p>
          <code className="vetor">{s.cvss?.vetor}</code>
          <table className="tabela-vetor">
            <tbody>
              {linhas.map((l) => (
                <tr key={l.valor}>
                  <th scope="row">{l.metrica} <code>{l.valor}</code></th>
                  <td>{l.traducao}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {!fim && (
        <details className="detalhes" onToggle={(e) => { if (e.currentTarget.open) buscar(); }}>
          <summary>Descrição oficial e referências, em inglês</summary>
          {s.titulo && <p><strong>{s.titulo}</strong></p>}
          {s.descricao && <p className="descricao">{s.descricao}</p>}
          {buscando && <p className="dica">Buscando no registro…</p>}
          {eCve && extra && extra.estado !== "publicado" && <p className="dica">Não consegui buscar a descrição agora. O veredito acima não depende dela.</p>}
          <ul className="referencias">
            {eCve && <li><a href={`https://www.cve.org/CVERecord?id=${s.id}`} target="_blank" rel="noreferrer">Registro em cve.org</a></li>}
            {s.referencias?.map((r) => <li key={r}><a href={r} target="_blank" rel="noreferrer noopener">{r}</a></li>)}
          </ul>
        </details>
      )}

      <div className="acoes-resultado">
        <button className="botao-secundario" onClick={() => void copiar()}>
          {copiado ? <><Check size={20} aria-hidden /> Copiado</> : <><Copy size={20} aria-hidden /> Copiar para o grupo em pânico</>}
        </button>
      </div>
    </section>
  );
}

export function Lista({ itens, origem, cortados, privados, semVersao, busca, exposta, abrir, voltar }: {
  itens: Item[]; origem: string; cortados: number; privados: number; semVersao: number; busca?: { texto: string; total: number; ignoradas: string[]; parcial: boolean }; exposta: Exposta; abrir: (i: Item) => void; voltar: () => void;
}) {
  const julgados = itens.map((item) => ({ item, v: vereditoDe(item, exposta.valor) }));
  if (!busca) julgados.sort((a, b) => ORDEM[a.v.nivel] - ORDEM[b.v.nivel] || (b.item.sinais.epss ?? 0) - (a.item.sinais.epss ?? 0));
  const contagem = (n: Nivel) => julgados.filter((j) => j.v.nivel === n).length;
  const pior = julgados[0]?.v.nivel;
  const niveis: Nivel[] = ["acorda", "cedo", "incerto", "olho", "dorme", "inexistente"];

  return (
    <section className="resultado">
      <button className="voltar" onClick={voltar}><ArrowLeft size={18} aria-hidden /> Consultar outro</button>
      {busca ? (
        <div className="cabeca-busca">
          <h1>{itens.length ? "Achei isto" : "Não achei nada"}</h1>
          <p className="busca-texto">{busca.texto.length > 120 ? `${busca.texto.slice(0, 120)}…` : busca.texto}</p>
          {itens.length > 0 && <p className="dica">{busca.total > itens.length ? `Os ${itens.length} mais relevantes de ${busca.total}.` : busca.parcial ? "Os mais relevantes entre os mais importantes, e pode haver mais." : "Os mais relevantes primeiro."} Cada veredito vale para quem usa aquele produto.</p>}
          {busca.ignoradas.length > 0 && itens.length > 0 && <p className="dica">Não aparecem em nenhum CVE: {busca.ignoradas.join(", ")}.</p>}
          {!itens.length && <p>Isso não quer dizer que não exista falha nesse produto, só que não achei com essas palavras. As descrições oficiais são em inglês: vale tentar o nome do fabricante ou menos palavras.</p>}
        </div>
      ) : !itens.length ? (
        <div className="veredito dorme">
          <BedDouble size={56} aria-hidden />
          <h1>Dorme em paz.</h1>
          <p>Nenhuma vulnerabilidade conhecida nessas versões. Até amanhã, pelo menos.</p>
        </div>
      ) : (
        <div className={`veredito ${pior}`}>
          {(() => { const I = ICONES[pior]; return <I size={56} aria-hidden />; })()}
          <h1>{TITULOS[pior]}</h1>
          <p>{pior === "acorda" ? contagem("acorda") === itens.length ? `Todos os ${itens.length} pedem atenção agora. Boa sorte.` : `${contagem("acorda")} de ${itens.length} ${contagem("acorda") === 1 ? "pede" : "pedem"} atenção agora. O resto pode esperar.` : `Nada pede madrugada entre os ${itens.length} itens.`}</p>
        </div>
      )}
      {!busca && <p className="dica origem">{origem}.{cortados > 0 ? ` Ficaram de fora ${cortados} CVEs: o limite é 200 por vez.` : ""}{privados > 0 ? ` Pacotes privados não consultados: ${privados}.` : ""}{semVersao > 0 ? ` Sem versão fixa, não consultados: ${semVersao}.` : ""}</p>}

      {itens.length > 0 && (
        <>
          <Exposicao_ exposta={exposta} />
          <div className="contagem">
            {niveis.filter((n) => contagem(n) > 0).map((n) => <span key={n} className={`selo-nivel ${n}`}>{ROTULOS[n]}: {contagem(n)}</span>)}
          </div>
          <ul className="lista">
            {julgados.map(({ item, v }) => {
              const I = ICONES[v.nivel];
              return (
                <li key={`${item.pacote?.nome ?? ""}${item.pacote?.versao ?? ""}${item.sinais.id}`}>
                  <button className={`linha ${v.nivel}`} onClick={() => abrir(item)}>
                    <span className="linha-icone"><I size={22} aria-hidden /></span>
                    <span className="linha-corpo">
                      <span className="linha-id">{item.sinais.id}</span>
                      <span className="linha-nome">{item.pacote ? `${item.pacote.nome} ${item.pacote.versao}` : item.sinais.produto ?? item.sinais.titulo ?? item.sinais.resumo ?? ""}</span>
                      {busca && item.sinais.produto && (item.sinais.titulo ?? item.sinais.resumo) && <span className="linha-titulo">{item.sinais.titulo ?? item.sinais.resumo}</span>}
                    </span>
                    <span className="linha-dados">
                      {item.sinais.kev && <span className="chip ruim">KEV</span>}
                      {item.sinais.rce && <span className="chip">RCE</span>}
                      {item.sinais.malicioso && <span className="chip ruim">Malicioso</span>}
                      {item.pacote?.soDev && <span className="chip">Dev</span>}
                      <span className={`selo-nivel ${v.nivel}`}>{ROTULOS[v.nivel]}</span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}

export function Confirmar({ leitura, confirmar, voltar }: { leitura: LeituraPacotes; confirmar: () => void; voltar: () => void }) {
  const { pacotes, privados, semVersao, formato } = leitura;
  return (
    <section className="resultado">
      <button className="voltar" onClick={voltar}><ArrowLeft size={18} aria-hidden /> Voltar</button>
      <h1>Antes de sair daqui</h1>
      <p className="grande">Achei {pacotes.length === 1 ? "1 pacote" : `${pacotes.length} pacotes`} em {formato}. Para conferir, nomes e versões vão para o OSV, um banco público de vulnerabilidades. O resto do arquivo fica no seu aparelho.</p>
      {privados > 0 && <p className="dica">Pacotes de registro privado que ficaram de fora: {privados}.</p>}
      {semVersao > 0 && <p className="dica">Sem versão fixa, que ficaram de fora: {semVersao}. Sem versão não dá para saber se está vulnerável.</p>}
      {formato !== "package-lock.json" && <p className="aviso-leve">Nesse formato não dá para saber o que é privado. Se tiver pacote interno com nome sensível, veja a lista abaixo antes de continuar.</p>}
      <details className="detalhes">
        <summary>Ver o que vai ser enviado</summary>
        <ul className="enviados">{pacotes.map((p) => <li key={`${p.nome}@${p.versao}`}><code>{p.nome} {p.versao}</code></li>)}</ul>
      </details>
      <button className="botao-gigante" onClick={confirmar}><Send size={26} aria-hidden /> Pode consultar</button>
    </section>
  );
}
