import { describe, expect, it } from "vitest";
import { lerRegistroCve, sinaisDeOsv } from "./fontes";

describe("lerRegistroCve", () => {
  it("rejeitado", () => {
    expect(lerRegistroCve({ cveMetadata: { state: "REJECTED" }, containers: { cna: {} } }).estado).toBe("rejeitado");
  });
  it("pega a nota do complemento da CISA quando o fornecedor não deu nenhuma", () => {
    const r = lerRegistroCve({
      cveMetadata: { state: "PUBLISHED", datePublished: "2021-12-10T00:00:00.000Z" },
      containers: {
        cna: {
          title: "Falha", descriptions: [{ lang: "es", value: "hola" }, { lang: "en", value: "hello" }],
          affected: [{ vendor: "n/a", product: "n/a" }, { vendor: "Apache", product: "Log4j2" }],
          metrics: [{ other: { type: "unknown", content: {} } }],
          references: [{ url: "https://exemplo.org/a" }, { url: "javascript:alert(1)" }],
        },
        adp: [{
          metrics: [
            { cvssV3_1: { baseScore: 10, vectorString: "CVSS:3.1/AV:N" } },
            { other: { type: "ssvc", content: { options: [{ Exploitation: "active" }, { Automatable: "yes" }] } } },
          ],
        }],
      },
    });
    expect(r.cvss).toEqual({ nota: 10, vetor: "CVSS:3.1/AV:N" });
    expect(r.exploracao).toBe("active");
    expect(r.automatizavel).toBe(true);
    expect(r.descricao).toBe("hello");
    expect(r.produto).toBe("Apache Log4j2");
    expect(r.referencias).toEqual(["https://exemplo.org/a"]);
  });
  it("prefere a nota mais nova do CVSS", () => {
    const r = lerRegistroCve({
      containers: { cna: { metrics: [{ cvssV3_1: { baseScore: 7, vectorString: "a" } }, { cvssV4_0: { baseScore: 8, vectorString: "b" } }] } },
    });
    expect(r.cvss?.nota).toBe(8);
  });
});

describe("sinaisDeOsv", () => {
  it("reconhece pacote malicioso pelo ID e pelo CWE", () => {
    expect(sinaisDeOsv({ id: "MAL-2025-1" }).malicioso).toBe(true);
    expect(sinaisDeOsv({ id: "GHSA-x", database_specific: { cwe_ids: ["CWE-506"] } }).malicioso).toBe(true);
    expect(sinaisDeOsv({ id: "GHSA-y", database_specific: { cwe_ids: ["CWE-79"] } }).malicioso).toBeFalsy();
  });
  it("faixa sem número vira nota aproximada", () => {
    const s = sinaisDeOsv({ id: "GHSA-z", database_specific: { severity: "HIGH" } });
    expect(s.cvss).toMatchObject({ aproximada: true, rotulo: "alta" });
  });
});
