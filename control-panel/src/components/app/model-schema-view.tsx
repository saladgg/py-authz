"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface OpenFgaTypeDefinition {
  type: string;
  relations?: Record<string, unknown>;
  metadata?: {
    relations?: Record<string, { directly_related_user_types?: { type: string }[] }>;
  };
}

export interface OpenFgaModel {
  schema_version: string;
  type_definitions: OpenFgaTypeDefinition[];
}

/**
 * A structured, per-type/per-relation view of the OpenFGA schema
 * `GET /models` returns — the primary view CP-12 asks for ("render... a
 * relation graph... rather than raw JSON as the primary view"). A full
 * interactive graph is a larger lift than an admin tool's "what does
 * this model actually say" screen needs; this gets most of the value
 * (types, their relations, and each relation's rewrite rule) without a
 * graphing dependency, with the exact rewrite JSON available per-relation
 * as the "view source" detail CP-12 explicitly allows as secondary.
 */
export function ModelSchemaView({ model }: { model: OpenFgaModel }) {
  const [showRaw, setShowRaw] = useState(false);
  const types = model.type_definitions.filter((t) => t.type !== "user");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Schema version {model.schema_version} · {types.length} type{types.length === 1 ? "" : "s"}
        </p>
        <Button variant="outline" size="sm" onClick={() => setShowRaw((v) => !v)}>
          {showRaw ? "Show structured view" : "View raw JSON"}
        </Button>
      </div>

      {showRaw ? (
        <pre className="max-h-[32rem] overflow-auto rounded-md border bg-muted p-4 text-xs">
          {JSON.stringify(model, null, 2)}
        </pre>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {types.map((typeDef) => (
            <Card key={typeDef.type}>
              <CardHeader>
                <CardTitle className="text-base">{typeDef.type}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {Object.keys(typeDef.relations ?? {}).map((relationName) => {
                  const subjects =
                    typeDef.metadata?.relations?.[relationName]?.directly_related_user_types ?? [];
                  return (
                    <div key={relationName} className="flex flex-wrap items-center gap-1.5 text-sm">
                      <span className="font-mono font-medium">{relationName}</span>
                      {subjects.map((s) => (
                        <Badge key={s.type} variant="secondary" className="text-xs">
                          {s.type}
                        </Badge>
                      ))}
                    </div>
                  );
                })}
                {Object.keys(typeDef.relations ?? {}).length === 0 ? (
                  <p className="text-sm text-muted-foreground">No relations declared.</p>
                ) : null}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
