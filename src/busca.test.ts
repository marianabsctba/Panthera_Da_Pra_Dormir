import { describe, expect, it } from "vitest";
import { baldeDe, buscarEm, palavras, TETO_PALAVRA, type Balde } from "./busca";

function indice(mapa: Record<string, string[] | { total: number; ids: string[] }>) {
  const baldes: Record<string, Balde> = {};
  for (const [p, v] of Object.entries(mapa)) {
    const ids = Array.isArray(v) ? v : v.ids;
    const total = Array.isArray(v) ? v.length : v.total;
    (baldes[baldeDe(p)] ??= {})[p] = [total, ...ids];
  }
  return async (nome: string) => baldes[nome] ?? {};
}

describe("palavras", () => {
  it("tira acento, maiúscula e palavra vazia", () => {
    expect(palavras("Execução de código NO Apache")).toEqual(["execucao", "codigo", "apache"]);
  });
  it("guarda o nome composto e as partes", () => {
    expect(palavras("log4j-core")).toEqual(["log4j-core", "log4j", "core"]);
  });
  it("ignora número solto e CVE", () => {
    expect(palavras("cve 2021 openssl")).toEqual(["openssl"]);
  });
});

describe("buscarEm", () => {
  it("exige todas as palavras em busca curta", async () => {
    const r = await buscarEm("fortinet ssl", indice({ fortinet: ["1", "2", "3"], ssl: ["2", "9"] }));
    expect(r.ids).toEqual(["2"]);
  });
  it("palavra cortada não exclui resultado, só ajuda a ordenar", async () => {
    const r = await buscarEm("wordpress fortinet", indice({ fortinet: ["1", "2", "3"], wordpress: { total: TETO_PALAVRA + 10, ids: ["3", "8"] } }));
    expect(r.ids).toEqual(["3", "1", "2"]);
  });
  it("só palavras cortadas: fica com quem tem todas", async () => {
    const r = await buscarEm("remote server", indice({ remote: { total: 99999, ids: ["1", "2"] }, server: { total: 88888, ids: ["2", "3"] } }));
    expect(r.ids).toEqual(["2"]);
  });
  it("palavra desconhecida é avisada, não vira zero resultado", async () => {
    const r = await buscarEm("openssl xyzzyqq", indice({ openssl: ["1"] }));
    expect(r.ids).toEqual(["1"]);
    expect(r.ignoradas).toEqual(["xyzzyqq"]);
  });
  it("nada encontrado devolve lista vazia", async () => {
    const r = await buscarEm("xyzzyqq", indice({}));
    expect(r.ids).toEqual([]);
    expect(r.total).toBe(0);
  });
  it("trecho longo ordena por quantas palavras batem e aceita parte delas", async () => {
    const r = await buscarEm("alpha bravo charlie delta echo foxtrot", indice({
      alpha: ["1", "2"], bravo: ["1", "2"], charlie: ["1", "2"], delta: ["1"], echo: ["1"], foxtrot: ["7"],
    }));
    expect(r.ids).toEqual(["1", "2"]);
  });
  it("traduz a busca em português", async () => {
    const r = await buscarEm("injeção", indice({ injection: ["5"] }));
    expect(r.ids).toEqual(["5"]);
  });
  it("acha apelido famoso, inclusive separado", async () => {
    expect((await buscarEm("Log4Shell", indice({}))).ids).toEqual(["2021-44228"]);
    expect((await buscarEm("dirty cow", indice({}))).ids).toEqual(["2016-5195"]);
    expect((await buscarEm("heartbleed", indice({}))).ignoradas).toEqual([]);
  });
  it("marca quando a busca pede execução de código", async () => {
    expect((await buscarEm("fortinet rce", indice({ fortinet: ["1"], rce: { total: 60000, ids: ["1"] } }))).querRce).toBe(true);
  });
});
