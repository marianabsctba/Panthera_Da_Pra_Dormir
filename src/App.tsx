import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowUpRight, BedDouble, FileUp, Flame, Github, Loader2, Moon, Skull, Sun, TrendingUp } from "lucide-react";
import ComoDecide from "./ComoDecide";
import { Confirmar, Detalhe, Lista, type Exposta } from "./Resultado";
import { LIMITE_CVES, extrairCves, lerPacotes } from "./entrada";
import { buscar, consultarCve, consultarPacotes, emParalelo, hoje as lerHoje } from "./fontes";
import { porcentagem } from "./veredito";
import type { Exposicao, Hoje, Item, LeituraPacotes } from "./tipos";

type Tela =
  | { nome: "inicio"; erro?: string }
  | { nome: "carregando"; etapa: string }
  | { nome: "confirmar"; leitura: LeituraPacotes }
  | { nome: "lista"; itens: Item[]; origem: string; cortados: number; privados: number; semVersao: number; busca?: { texto: string; total: number; ignoradas: string[]; parcial: boolean } }
  | { nome: "detalhe"; item: Item };

const DIAS_VELHO = 3;
const CVE_NO_HASH = /^#(CVE-\d{4}-\d{4,})$/i;
const BUSCA_NO_HASH = /^#busca=(.+)$/;

function preferencia(chave: string): string | null {
  try { return localStorage.getItem(chave); } catch { return null; }
}
function gravar(chave: string, valor: string) {
  try { localStorage.setItem(chave, valor); } catch { /* sem armazenamento */ }
}

function dataBr(iso: string): string {
  const [a, m, d] = iso.split("-");
  return `${d}/${m}/${a}`;
}

export default function App() {
  const [tela, setTela] = useState<Tela>({ nome: "inicio" });
  const [como, setComo] = useState(location.hash === "#como");
  const [texto, setTexto] = useState("");
  const [dados, setDados] = useState<Hoje | null>(null);
  const [exposicao, setExposicao] = useState<Exposicao>("nao_sei");
  const [voltarLista, setVoltarLista] = useState<Extract<Tela, { nome: "lista" }> | null>(null);
  const [tema, setTema] = useState<"claro" | "escuro">(() => {
    const t = preferencia("dormir:tema");
    if (t === "claro" || t === "escuro") return t;
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "claro" : "escuro";
  });
  const entrada = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.documentElement.dataset.tema = tema;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", tema === "claro" ? "#ffffff" : "#0b0b0b");
    gravar("dormir:tema", tema);
  }, [tema]);

  useEffect(() => { void lerHoje().then(setDados); }, []);

  const umCve = useCallback(async (id: string, lista: Extract<Tela, { nome: "lista" }> | null) => {
    setComo(false);
    setVoltarLista(lista);
    setTela({ nome: "carregando", etapa: `Consultando ${id}` });
    const sinais = await consultarCve(id);
    setTela({ nome: "detalhe", item: { sinais } });
    window.scrollTo(0, 0);
  }, []);

  const pesquisar = useCallback(async (texto: string) => {
    setComo(false);
    setVoltarLista(null);
    setTela({ nome: "carregando", etapa: "Procurando" });
    try {
      const r = await buscar(texto);
      setTela({ nome: "lista", itens: r.itens, origem: "", cortados: 0, privados: 0, semVersao: 0, busca: { texto, total: r.total, ignoradas: r.ignoradas, parcial: r.parcial } });
      window.scrollTo(0, 0);
    } catch (e) {
      console.error(e);
      setTela({ nome: "inicio", erro: "Não consegui fazer a busca agora. Tente de novo em alguns minutos." });
    }
  }, []);

  // Link compartilhado: o CVE ou a busca vêm no endereço.
  useEffect(() => {
    const seguir = () => {
      setComo(location.hash === "#como");
      const m = CVE_NO_HASH.exec(location.hash);
      if (m) { void umCve(m[1].toUpperCase(), null); return; }
      const b = BUSCA_NO_HASH.exec(location.hash);
      if (b) void pesquisar(decodeURIComponent(b[1]));
    };
    seguir();
    window.addEventListener("hashchange", seguir);
    return () => window.removeEventListener("hashchange", seguir);
  }, [umCve, pesquisar]);

  const inicio = () => {
    history.replaceState(null, "", location.pathname + location.search);
    setComo(false);
    setVoltarLista(null);
    setTela({ nome: "inicio" });
    window.scrollTo(0, 0);
  };

  const analisar = useCallback(async (bruto: string) => {
    const leitura = lerPacotes(bruto);
    if (leitura) {
      if (!leitura.pacotes.length) {
        setTela({ nome: "inicio", erro: "Esse arquivo não tem nenhum pacote público com versão fixa para consultar." });
        return;
      }
      setTela({ nome: "confirmar", leitura });
      window.scrollTo(0, 0);
      return;
    }
    const cves = extrairCves(bruto);
    if (!cves.length) {
      const hash = `#busca=${encodeURIComponent(bruto.trim().slice(0, 500))}`;
      if (location.hash === hash) void pesquisar(bruto.trim().slice(0, 500));
      else location.hash = hash;
      return;
    }
    if (cves.length === 1) { location.hash = cves[0]; return; }
    const usados = cves.slice(0, LIMITE_CVES);
    setTela({ nome: "carregando", etapa: `Consultando ${usados.length} CVEs` });
    const sinais = await emParalelo(usados, consultarCve, (f) => setTela({ nome: "carregando", etapa: `Consultando ${f} de ${usados.length} CVEs` }));
    setTela({ nome: "lista", itens: sinais.map((s) => ({ sinais: s })), origem: `${usados.length} CVEs colados`, cortados: cves.length - usados.length, privados: 0, semVersao: 0 });
    window.scrollTo(0, 0);
  }, [pesquisar]);

  const consultar = useCallback(async (l: LeituraPacotes) => {
    setTela({ nome: "carregando", etapa: "Consultando" });
    try {
      const itens = await consultarPacotes(l.pacotes, (etapa) => setTela({ nome: "carregando", etapa }));
      setTela({ nome: "lista", itens, origem: `${l.pacotes.length} pacotes de ${l.formato}`, cortados: 0, privados: l.privados, semVersao: l.semVersao });
      window.scrollTo(0, 0);
    } catch (e) {
      console.error(e);
      setTela({ nome: "inicio", erro: "Não consegui falar com o banco de vulnerabilidades. Tente de novo em alguns minutos." });
    }
  }, []);

  const arquivo = async (f: File | undefined) => {
    if (!f) return;
    setComo(false);
    await analisar(await f.text());
  };

  const velho = dados && (Date.now() - Date.parse(dados.dataEpss)) / 86400000 > DIAS_VELHO;
  const exposta: Exposta = { valor: exposicao, mudar: setExposicao };

  return (
    <div className="app" onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); void arquivo(e.dataTransfer.files[0]); }}>
      <header className="topo">
        <a className="marca" href="./" onClick={(e) => { e.preventDefault(); inicio(); }}>
          <img src={`${import.meta.env.BASE_URL}pantera.webp`} alt="" />
          <span className="nome">PANTHERA DÁ PRA DORMIR?</span>
        </a>
        <button className="tema" aria-label={tema === "claro" ? "Usar fundo escuro" : "Usar fundo claro"} title={tema === "claro" ? "Fundo escuro" : "Fundo claro"}
          onClick={() => setTema(tema === "claro" ? "escuro" : "claro")}>
          {tema === "claro" ? <Moon size={20} /> : <Sun size={20} />}
        </button>
      </header>

      <main className="conteudo">
        {como ? (
          <ComoDecide voltar={inicio} />
        ) : tela.nome === "carregando" ? (
          <section className="lendo" aria-live="polite">
            <Loader2 size={56} className="gira" aria-hidden />
            <p className="grande">{tela.etapa}…</p>
          </section>
        ) : tela.nome === "confirmar" ? (
          <Confirmar leitura={tela.leitura} confirmar={() => void consultar(tela.leitura)} voltar={inicio} />
        ) : tela.nome === "lista" ? (
          <Lista {...tela} exposta={exposta} voltar={inicio} abrir={(item) => {
            setVoltarLista(tela);
            setTela({ nome: "detalhe", item });
            window.scrollTo(0, 0);
          }} />
        ) : tela.nome === "detalhe" ? (
          <Detalhe key={tela.item.sinais.id} item={tela.item} exposta={exposta}
            voltar={() => {
              if (voltarLista) { history.replaceState(null, "", location.pathname + location.search); setTela(voltarLista); setVoltarLista(null); }
              else inicio();
            }}
            rotuloVoltar={voltarLista ? "Voltar para a lista" : "Consultar outro"} />
        ) : (
          <section className="inicio">
            <h1>Dá pra dormir?</h1>
            <p className="grande">Saiu uma falha com manchete apocalíptica e o grupo da empresa já está em chamas? Cola aqui. A gente separa o incêndio do barulho.</p>
            {tela.erro && <p className="aviso-erro" role="alert">{tela.erro}</p>}
            <form onSubmit={(e) => { e.preventDefault(); void analisar(texto); }}>
              <label className="sr" htmlFor="entrada">CVE, produto, palavra, trecho, boletim ou lista de dependências</label>
              <textarea id="entrada" rows={4} value={texto} onChange={(e) => setTexto(e.target.value)} spellCheck={false}
                placeholder="CVE-2021-44228, fortinet rce, heartbleed, um trecho de boletim ou um package-lock.json" />
              <button className="botao-gigante" type="submit" disabled={!texto.trim()}>
                <BedDouble size={30} aria-hidden /> Posso dormir?
              </button>
            </form>
            <input ref={entrada} type="file" hidden accept=".json,.txt,.mod,.lock"
              onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; void arquivo(f); }} />
            <button className="botao-secundario" onClick={() => entrada.current?.click()}>
              <FileUp size={20} aria-hidden /> Abrir package-lock.json, requirements.txt ou go.mod
            </button>
            {velho && <p className="aviso-leve">Os dados locais são de {dataBr(dados!.dataEpss)}. Pode ter novidade que ainda não chegou aqui.</p>}

            {dados && (
              <div className="paineis">
                <section>
                  <h2><Skull size={20} aria-hidden /> Entrou na lista de quem já está apanhando</h2>
                  <ul className="feed">
                    {dados.recentes.map((r) => (
                      <li key={r.id}>
                        <a href={`#${r.id}`}>
                          <span className="feed-id">{r.id}</span>
                          <span className="feed-nome">{r.nome}</span>
                          <span className="feed-info">{dataBr(r.desde)}{r.ransomware ? ", com ransomware" : ""}</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </section>
                <section>
                  <h2><TrendingUp size={20} aria-hidden /> Esquentou esta semana</h2>
                  <ul className="feed">
                    {dados.subindo.map((s) => (
                      <li key={s.id}>
                        <a href={`#${s.id}`}>
                          <span className="feed-id">{s.id}</span>
                          {s.nome && <span className="feed-nome">{s.nome}</span>}
                          <span className="feed-info"><Flame size={14} aria-hidden /> EPSS de {porcentagem(s.antes)} para {porcentagem(s.epss)}</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </section>
              </div>
            )}
            <a className="link-grande" href="#como">Como a gente decide (e por que a nota sozinha não basta) <ArrowUpRight size={16} aria-hidden /></a>
          </section>
        )}
      </main>

      <footer className="rodape">
        <a href="#como">Como a gente decide</a>
        {dados && <span>Dados de {dataBr(dados.dataEpss)}</span>}
        <a href="https://github.com/marianabsctba/Panthera_Da_Pra_Dormir" target="_blank" rel="noreferrer"><Github size={16} aria-hidden /> Código aberto</a>
      </footer>
    </div>
  );
}
