import type { ReactNode } from "react";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export interface DataTableColumn<T> {
  header: string;
  cell: (row: T) => ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  emptyMessage?: string;
}

/**
 * Shared read-mostly table — every list screen in this app (Tenants,
 * Service Accounts, Audit Log, ...) renders through this instead of a
 * one-off `<table>` per screen (see the architecture doc's "shared
 * <DataTable>" component, CP-11). Deliberately not built on
 * @tanstack/react-table — nothing here needs client-side sort/filter/
 * pagination beyond what each screen's own server-side query params
 * already provide, so a generic typed wrapper over shadcn's `<Table>`
 * primitives is enough.
 */
export function DataTable<T>({ columns, rows, rowKey, emptyMessage }: DataTableProps<T>) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead key={column.header} className={column.className}>
                {column.header}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={columns.length} className="h-24 text-center text-muted-foreground">
                {emptyMessage ?? "Nothing to show."}
              </TableCell>
            </TableRow>
          ) : (
            rows.map((row) => (
              <TableRow key={rowKey(row)}>
                {columns.map((column) => (
                  <TableCell key={column.header} className={column.className}>
                    {column.cell(row)}
                  </TableCell>
                ))}
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
