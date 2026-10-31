# Dá Pra Dormir?

Saiu uma vulnerabilidade com manchete apocalíptica? Cole o CVE, um boletim inteiro ou a lista de dependências do projeto, e receba o veredito: acordar alguém agora ou dormir em paz.

O objetivo é ensinar a priorizar. O CVSS mede o estrago possível, o EPSS estima a chance de exploração e o KEV confirma a exploração em andamento. Cada veredito mostra o motivo e traduz o vetor CVSS para português.

## Como funciona

- Site estático, sem servidor, publicado no GitHub Pages.
- Um GitHub Action roda todo dia e baixa o [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) e o [EPSS](https://www.first.org/epss/). O script `scripts/dados.mjs` divide os dados em arquivos pequenos por ano e dois últimos dígitos do CVE, e o navegador baixa só o que precisa. Se um feed vier cortado, a publicação falha e o site fica com os dados do dia anterior.
- Gravidade, descrição e dados de SSVC vêm do [registro público de CVEs](https://www.cve.org/), consultado pelo navegador.
- Dependências são consultadas no [OSV](https://osv.dev/), depois de a pessoa confirmar. Vão só nomes e versões. Pacotes de registro privado do `package-lock.json` ficam de fora.

## O critério

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
