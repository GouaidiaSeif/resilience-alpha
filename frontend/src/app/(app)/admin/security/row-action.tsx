"use client";

import { useActionState } from "react";

import { unbanIp, unblockClient, type RowActionState } from "@/actions/security";
import { Button } from "@/components/ui/button";

/** Bouton d'une ligne de tableau (débannir une IP, débloquer un client ML), avec erreur affichée sur place. */
export function RowAction({ kind, target, label }: { kind: "unban" | "unblock"; target: string; label: string }) {
  const bound = (kind === "unban" ? unbanIp : unblockClient).bind(null, target);
  const [state, action, pending] = useActionState<RowActionState>(bound, {});
  const text = kind === "unban" ? "Débannir" : "Débloquer";
  return (
    <form action={action} className="flex flex-col items-end gap-1">
      <Button type="submit" size="sm" loading={pending} loadingLabel={`${text}…`} aria-label={`${text} ${label}`}>
        {text}
      </Button>
      {state.message ? (
        <p role="alert" className="max-w-48 text-right text-[12px] leading-4 text-danger">
          {state.message}
        </p>
      ) : null}
    </form>
  );
}
