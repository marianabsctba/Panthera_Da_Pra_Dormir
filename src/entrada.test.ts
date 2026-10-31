import { describe, expect, it } from "vitest";
import { extrairCves, lerPacotes } from "./entrada";
import { explicarVetor } from "./vetor";

describe("extrairCves", () => {
  it("acha no meio do texto, sem repetir", () => {
    expect(extrairCves("URGENTE!!! cve-2021-44228 e CVE-2026-118527, de novo CVE-2021-44228")).toEqual(["CVE-2021-44228", "CVE-2026-118527"]);
  });
  it("ignora o que não é CVE", () => {
    expect(extrairCves("CVE-21-1 GHSA-29mw-wpgm-hmr9")).toEqual([]);
  });
});

describe("lerPacotes", () => {
  it("package-lock v3: caminho aninhado, escopo, dev e privado", () => {
    const l = lerPacotes(JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/lodash": { version: "4.17.15", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" },
        "node_modules/a/node_modules/@b/c": { version: "1.0.0", resolved: "https://registry.npmjs.org/@b/c/-/c-1.0.0.tgz", dev: true },
        "node_modules/@empresa/segredo": { version: "1.0.0", resolved: "https://npm.empresa.local/segredo.tgz" },
        "node_modules/ligado": { link: true },
        "packages/local": { version: "1.0.0" },
      },
    }));
    expect(l?.pacotes).toEqual([
      { nome: "lodash", versao: "4.17.15", ecossistema: "npm", soDev: false },
      { nome: "@b/c", versao: "1.0.0", ecossistema: "npm", soDev: true },
    ]);
    expect(l?.privados).toBe(1);
  });
  it("mesma versão em produção e em dev conta como produção", () => {
    const l = lerPacotes(JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/x": { version: "1.0.0", dev: true },
        "node_modules/y/node_modules/x": { version: "1.0.0" },
      },
    }));
    expect(l?.pacotes).toEqual([{ nome: "x", versao: "1.0.0", ecossistema: "npm", soDev: false }]);
  });
  it("package-lock v1 recursivo", () => {
    const l = lerPacotes(JSON.stringify({
      lockfileVersion: 1,
      dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0", dev: true } } }, c: { version: "git+https://x/y.git" } },
    }));
    expect(l?.pacotes.map((p) => p.nome)).toEqual(["a", "b"]);
    expect(l?.privados).toBe(1);
  });
  it("requirements.txt", () => {
    const l = lerPacotes("# comentário\nrequests[socks]==2.19.0  # velho\nflask>=2\n-r outro.txt\ndjango==3.2.1 ; python_version > '3.6'\n");
    expect(l?.pacotes.map((p) => `${p.nome} ${p.versao}`)).toEqual(["requests 2.19.0", "django 3.2.1"]);
    expect(l?.semVersao).toBe(1);
  });
  it("go.mod, nos dois formatos de require", () => {
    const l = lerPacotes("module exemplo.com/app\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\n\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n)\n");
    expect(l?.pacotes.map((p) => `${p.nome} ${p.versao}`)).toEqual(["github.com/a/b v1.2.3", "golang.org/x/net v0.1.0"]);
  });
  it("texto comum com CVE não vira lista de pacotes", () => {
    expect(lerPacotes("Bom dia, saiu o CVE-2021-44228, é grave?\nAbraços")).toBeNull();
    expect(lerPacotes("CVE-2021-44228")).toBeNull();
    expect(lerPacotes('{"a":1}')).toBeNull();
  });
});

describe("explicarVetor", () => {
  it("CVSS 3.1", () => {
    const l = explicarVetor("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(l).toHaveLength(8);
    expect(l[0].traducao).toMatch(/internet/);
  });
  it("CVSS 4.0", () => {
    const l = explicarVetor("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(l).toHaveLength(11);
  });
  it("sem vetor, sem linhas", () => {
    expect(explicarVetor(undefined)).toEqual([]);
  });
});
