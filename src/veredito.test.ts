import { describe, expect, it } from "vitest";
import { decidir } from "./veredito";
import type { Kev, Sinais } from "./tipos";

const AGORA = new Date("2026-10-31T12:00:00Z");
const REMOTO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
const KEV: Kev = { fornecedor: "X", produto: "Y", nome: "Z", desde: "2026-01-01", prazo: "2026-02-01", ransomware: false, acao: "", descricao: "" };

function s(extra: Partial<Sinais>): Sinais {
  return { id: "CVE-2026-0001", estado: "publicado", publicado: "2024-01-01", ...extra };
}
const nivel = (x: Partial<Sinais>, e: "internet" | "interna" | "nao_sei" = "nao_sei", dev = false) => decidir(s(x), e, dev, AGORA).nivel;

describe("decidir", () => {
  it("KEV acorda mesmo com EPSS e nota baixos", () => {
    expect(nivel({ kev: KEV, epss: 0.001, cvss: { nota: 4, vetor: REMOTO } })).toBe("acorda");
  });
  it("nota 9,8 remota sem sinal de exploração não acorda ninguém, mas põe o alarme", () => {
    expect(nivel({ epss: 0.002, cvss: { nota: 9.8, vetor: REMOTO } })).toBe("cedo");
    expect(nivel({ epss: 0.002, cvss: { nota: 9.8, vetor: REMOTO }, publicado: "2026-10-25" })).toBe("cedo");
  });
  it("nota crítica local não põe o alarme só pela nota", () => {
    expect(nivel({ epss: 0.002, cvss: { nota: 9.3, vetor: LOCAL } })).toBe("olho");
  });
  it("gravidade crítica sem vetor conta como remota até prova em contrário", () => {
    expect(nivel({ cvss: { nota: 9.5, aproximada: true, rotulo: "crítica" }, epss: 0.001 })).toBe("cedo");
  });
  it("nota crítica remota na rede interna baixa para a semana", () => {
    expect(nivel({ epss: 0.002, cvss: { nota: 9.8, vetor: REMOTO } }, "interna")).toBe("olho");
  });
  it("EPSS de 5% para cima põe o alarme", () => {
    expect(nivel({ epss: 0.08, cvss: { nota: 8.8, vetor: REMOTO } })).toBe("cedo");
  });
  it("CVSS 10 remoto com exploit público põe o alarme, mesmo com EPSS baixo e login comum (CVE-2026-39842)", () => {
    const x = { epss: 0.00924, exploracao: "poc" as const, automatizavel: false, publicado: "2026-04-14", cvss: { nota: 10, vetor: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" } };
    const v = decidir(s(x), "nao_sei", false, AGORA);
    expect(v.nivel).toBe("cedo");
    expect(v.motivos.find((m) => m.titulo.startsWith("EPSS"))?.tipo).toBe("atencao");
  });
  it("exploit público que exige admin não sobe sozinho", () => {
    expect(nivel({ epss: 0.005, exploracao: "poc", cvss: { nota: 9.1, vetor: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" } })).toBe("olho");
  });
  it("EPSS alto acorda, mesmo fora do KEV", () => {
    expect(nivel({ epss: 0.7, cvss: { nota: 7, vetor: REMOTO } })).toBe("acorda");
  });
  it("EPSS alto em ataque local só põe o alarme", () => {
    expect(nivel({ epss: 0.7, cvss: { nota: 7, vetor: LOCAL } })).toBe("cedo");
  });
  it("exploit público automatizável põe o alarme", () => {
    expect(nivel({ epss: 0.005, exploracao: "poc", automatizavel: true, cvss: { nota: 6, vetor: REMOTO } })).toBe("cedo");
  });
  it("nota baixa e EPSS baixo: dorme", () => {
    expect(nivel({ epss: 0.001, cvss: { nota: 3, vetor: REMOTO } })).toBe("dorme");
  });
  it("sem nota nunca dá dorme, mesmo com CVE antigo e EPSS baixo", () => {
    expect(nivel({ epss: 0.001 })).toBe("incerto");
  });
  it("execução de código nunca dá dorme, nem com todos os ajustes", () => {
    const x = { rce: true, epss: 0.001, cvss: { nota: 4.7, vetor: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L" } };
    expect(nivel(x)).toBe("olho");
    expect(nivel(x, "interna", true)).toBe("olho");
  });
  it("execução de código remota sem admin e com nota alta põe o alarme", () => {
    expect(nivel({ rce: true, epss: 0.001, cvss: { nota: 8, vetor: REMOTO } })).toBe("cedo");
    expect(nivel({ rce: true, epss: 0.001 })).toBe("cedo");
  });
  it("módulo pronto no Metasploit acorda em falha remota sem admin", () => {
    const exploits = [{ fonte: "metasploit" as const, url: "https://x" }];
    expect(nivel({ exploits, epss: 0.001, cvss: { nota: 6, vetor: REMOTO } })).toBe("acorda");
    expect(nivel({ exploits, epss: 0.001, cvss: { nota: 6, vetor: LOCAL } })).toBe("cedo");
  });
  it("modelo no Nuclei põe o alarme, e link citado só tira do dorme", () => {
    expect(nivel({ exploits: [{ fonte: "nuclei", url: "https://x" }], epss: 0.001, cvss: { nota: 5, vetor: REMOTO } })).toBe("cedo");
    expect(nivel({ exploits: [{ fonte: "registro", url: "https://x" }], epss: 0.001, cvss: { nota: 5, vetor: REMOTO } })).toBe("olho");
  });
  it("não achar exploit não vira motivo de tranquilidade", () => {
    const v = decidir(s({ epss: 0.001, cvss: { nota: 3, vetor: REMOTO } }), "nao_sei", false, AGORA);
    expect(v.motivos.find((m) => m.titulo === "Fora do KEV")?.tipo).toBe("info");
  });
  it("CVE-2025-3691: exploit citado e nota média fica na semana, sem texto alarmista", () => {
    const v = decidir(s({ epss: 0.00605, exploracao: "poc", automatizavel: false, cvss: { nota: 5.1, vetor: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N" } }), "nao_sei", false, AGORA);
    expect(v.nivel).toBe("olho");
    expect(v.motivos.find((m) => m.titulo.startsWith("EPSS"))?.texto).not.toMatch(/console/);
  });
  it("sem nota e sem EPSS não inventa veredito", () => {
    expect(nivel({})).toBe("incerto");
    expect(nivel({ estado: "sem_consulta", publicado: undefined })).toBe("incerto");
  });
  it("CVE recente com EPSS baixo e sem nota continua incerto", () => {
    expect(nivel({ epss: 0.001, publicado: "2026-10-30" })).toBe("incerto");
  });
  it("rede interna baixa um nível", () => {
    expect(nivel({ kev: KEV, cvss: { nota: 9, vetor: REMOTO } }, "interna")).toBe("cedo");
  });
  it("não sei conta como internet", () => {
    const x = { kev: KEV, cvss: { nota: 9, vetor: REMOTO } };
    expect(nivel(x, "nao_sei")).toBe(nivel(x, "internet"));
  });
  it("ransomware nunca baixa", () => {
    const x = { kev: { ...KEV, ransomware: true }, cvss: { nota: 7, vetor: LOCAL } };
    expect(nivel(x, "interna", true)).toBe("acorda");
  });
  it("dependência de desenvolvimento baixa um nível", () => {
    expect(nivel({ epss: 0.2, cvss: { nota: 7, vetor: REMOTO } }, "nao_sei", true)).toBe("olho");
  });
  it("rede interna e desenvolvimento somam, sem passar de dorme", () => {
    expect(nivel({ epss: 0.02, cvss: { nota: 7, vetor: REMOTO } }, "interna", true)).toBe("dorme");
  });
  it("pacote malicioso acorda sempre", () => {
    expect(nivel({ malicioso: true }, "interna", true)).toBe("acorda");
  });
  it("rejeitado e não encontrado não existem", () => {
    expect(nivel({ estado: "rejeitado" })).toBe("inexistente");
    expect(nivel({ estado: "nao_encontrado" })).toBe("inexistente");
  });
  it("sem registro público, mas com KEV, ainda acorda", () => {
    expect(nivel({ estado: "nao_encontrado", kev: KEV })).toBe("acorda");
  });
});
