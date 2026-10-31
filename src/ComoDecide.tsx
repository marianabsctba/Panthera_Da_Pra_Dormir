import { ArrowLeft } from "lucide-react";
import { TITULOS } from "./piadas";

export default function ComoDecide({ voltar }: { voltar: () => void }) {
  return (
    <section className="leitura">
      <button className="voltar" onClick={voltar}><ArrowLeft size={18} aria-hidden /> Voltar</button>
      <h1>Como a gente decide</h1>
      <p className="grande">Saem mais de cem CVEs por dia. Se você corrigir na ordem da nota, vai passar a vida apagando o incêndio errado.</p>

      <h2>Três perguntas, três fontes</h2>
      <div className="tres">
        <article>
          <h3>Quanto estrago faria?</h3>
          <p><strong>CVSS</strong>, a nota de 0 a 10. Mede o pior cenário em abstrato. Não sabe se alguém está atacando nem se você usa aquilo. Sozinha, serve para manchete.</p>
        </article>
        <article>
          <h3>Vão tentar?</h3>
          <p><strong>EPSS</strong>, a chance de exploração nos próximos 30 dias, calculada com dados de ataques reais. Muda todo dia. Não diz se o estrago seria grande.</p>
        </article>
        <article>
          <h3>Já estão fazendo?</h3>
          <p><strong>KEV</strong>, o catálogo da CISA, a agência de cibersegurança dos EUA. Só entra com exploração confirmada. É a resposta mais útil, e a que menos aparece na manchete.</p>
        </article>
      </div>

      <h2>A regra</h2>
      <table className="regra">
        <tbody>
          <tr className="acorda"><th scope="row">{TITULOS.acorda}</th><td>Está no KEV, ou tem exploração ativa, ou EPSS de 50% para cima.</td></tr>
          <tr className="cedo"><th scope="row">{TITULOS.cedo}</th><td>EPSS de 5% para cima, ou exploit público fácil de automatizar, ou nota 9 para cima em ataque remoto que não exige admin.</td></tr>
          <tr className="olho"><th scope="row">{TITULOS.olho}</th><td>Nota 7 para cima, ou EPSS de 1% para cima, ou exploit público.</td></tr>
          <tr className="dorme"><th scope="row">{TITULOS.dorme}</th><td>Todo o resto.</td></tr>
        </tbody>
      </table>

      <h2>O que baixa um nível</h2>
      <ul className="lista-grande">
        <li>Ficar só na rede interna, se você disser que fica.</li>
        <li>O ataque partir de dentro da máquina, quando o caso está no nível mais alto.</li>
        <li>A dependência só existir em desenvolvimento.</li>
      </ul>
      <p>Falha usada em ransomware não baixa nunca, porque ransomware anda pela rede. Pacote malicioso também não, porque ali o problema é o pacote inteiro.</p>

      <h2>O que a gente não sabe</h2>
      <ul className="lista-grande">
        <li>Se você usa mesmo o produto e a versão afetada.</li>
        <li>O que tem naquele servidor. Uma falha média no sistema que guarda dado de saúde pode ser pior que uma crítica no servidor de testes.</li>
        <li>Se já invadiram. Estar corrigido não significa estar limpo.</li>
        <li>O que ninguém confirmou ainda. Fora do KEV não quer dizer fora de perigo.</li>
        <li>O futuro. O EPSS costuma reagir depois do ataque: muita falha entra no KEV com EPSS baixo. Por isso, nota crítica e remota nunca fica só na fila.</li>
      </ul>
      <p>Isto é um ponto de partida para priorizar, não um parecer sobre o seu ambiente. Se o veredito contrariar o que você sabe da sua casa, confie no que você sabe.</p>

      <h2>O que sai do seu aparelho</h2>
      <p>O veredito de um CVE é calculado aqui, com os dados do dia, e o número não sai do seu aparelho. Ele só vai para o registro público de CVEs se for mais novo que os dados do dia, se ainda estiver sem nota, ou se você abrir a descrição oficial. Ao consultar dependências, nomes e versões vão para o OSV, depois de você confirmar. Nada fica guardado aqui.</p>
    </section>
  );
}
