import { describe, expect, it } from "vitest";
import { sinaisDeOsv } from "./fontes";
import { compactar, lerRegistroCve, parteLocal } from "./registro";
import { decidir } from "./veredito";

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

describe("compactar", () => {
  const registro: Parameters<typeof lerRegistroCve>[0] = {
    cveMetadata: { state: "PUBLISHED", datePublished: "2026-04-14T23:21:22.242Z" },
    containers: {
      cna: { title: "Falha", affected: [{ vendor: "x", product: "y" }], descriptions: [{ lang: "en", value: "texto longo" }], metrics: [{ cvssV3_1: { baseScore: 10, vectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" } }] },
      adp: [{ metrics: [{ other: { type: "ssvc", content: { options: [{ Exploitation: "poc" }, { Automatable: "no" }] } } }] }],
    },
  };
  it("o veredito é o mesmo com o registro completo e com o enxuto", () => {
    const completo = lerRegistroCve(registro);
    const enxuto = parteLocal(compactar(completo));
    const agora = new Date("2026-10-31T12:00:00Z");
    const a = decidir({ id: "CVE-2026-39842", ...completo, epss: 0.009 }, "nao_sei", false, agora);
    const b = decidir({ id: "CVE-2026-39842", ...enxuto, epss: 0.009 }, "nao_sei", false, agora);
    expect(b.nivel).toBe(a.nivel);
    expect(b.nivel).toBe("cedo");
    expect(b.motivos.map((m) => m.titulo)).toEqual(a.motivos.map((m) => m.titulo));
  });
  it("deixa a descrição de fora", () => {
    expect(JSON.stringify(compactar(lerRegistroCve(registro)))).not.toContain("texto longo");
  });
  it("rejeitado continua rejeitado", () => {
    expect(parteLocal(compactar({ estado: "rejeitado" })).estado).toBe("rejeitado");
  });
});
