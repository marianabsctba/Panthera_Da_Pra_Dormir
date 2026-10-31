# Dá Pra Dormir?

Saiu uma vulnerabilidade com manchete apocalíptica? Cole o CVE, um boletim inteiro ou a lista de dependências do projeto, e receba o veredito: acordar alguém agora ou dormir em paz.

O objetivo é ensinar a priorizar. O CVSS mede o estrago possível, o EPSS estima a chance de exploração e o KEV confirma a exploração em andamento. Cada veredito mostra o motivo e traduz o vetor CVSS para português.

## Como funciona

- Site estático, sem servidor, publicado no GitHub Pages.
- Um GitHub Action roda todo dia e baixa o [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), o [EPSS](https://www.first.org/epss/) e a [base inteira de CVEs](https://github.com/CVEProject/cvelistV5). O script `scripts/dados.mjs` guarda só o que o veredito usa e divide tudo em arquivos pequenos por ano e dois últimos dígitos do CVE, e o navegador baixa só o que precisa. Se uma fonte vier cortada, a publicação falha e o site fica com os dados do dia anterior.
- O [registro público de CVEs](https://www.cve.org/) é consultado pelo navegador só em três casos: CVE mais novo que os dados do dia, CVE ainda sem nota, ou quando a pessoa abre a descrição oficial.
- Dependências são consultadas no [OSV](https://osv.dev/), depois de a pessoa confirmar. Vão só nomes e versões. Pacotes de registro privado do `package-lock.json` ficam de fora.

## O critério

Três princípios: falta de dado nunca tranquiliza, sinal grave põe um piso e nem todo exploit pesa igual. A cada atualização, `scripts/avaliar.mjs` confere esses princípios contra todos os CVEs e contra casos reais. Se algum quebrar, nada é publicado. Com `npm run avaliar -- --historico`, repete a medida do KEV com o EPSS de antes de cada falha entrar na lista.

Os links de exploit vêm do Metasploit, do Nuclei, do Exploit-DB e das referências do próprio registro do CVE. O site só aponta para eles e não testa nenhum. Não aparecer nessas fontes não quer dizer que não exista.

A regra está em `src/veredito.ts`, com testes em `src/veredito.test.ts`, e é explicada no site. Os limites são uma escolha deste projeto, não um padrão da indústria.

## Rodar

```bash
npm ci
npm run dados
npm test
npm run build
npm run preview
```

## Dados

- KEV: CISA, sob CC0.
- EPSS: FIRST, com dados de Cyentia e Empirical Security.
- CVE: programa CVE, MITRE.
- OSV: Google, com os dados de cada ecossistema.

## Licença

GPL-3.0-or-later.
