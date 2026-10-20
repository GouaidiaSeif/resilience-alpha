"use server";

import { revalidatePath } from "next/cache";
import { headers } from "next/headers";

import { authed } from "@/lib/api";
import { BAN_DURATIONS } from "@/lib/constants";
import type { Ban } from "@/lib/types";

export interface BanFormState {
  ok?: string;
  message?: string;
  fieldErrors?: Partial<Record<"ip" | "reason" | "duration", string>>;
  values?: { ip: string; reason: string; duration: string };
}

export interface RowActionState {
  message?: string;
}

const IP_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$|^[0-9a-f:]{2,39}$/i;

/** Adresse du navigateur qui fait la demande, telle que transmise par le WAF (X-Forwarded-For, posé par lui seul). */
async function requesterIp(): Promise<string | null> {
  return (await headers()).get("x-forwarded-for")?.split(",")[0]?.trim() || null;
}

function unavailable(kind: string): boolean {
  return kind === "unavailable" || kind === "timeout" || kind === "unreachable";
}

export async function banIp(_prev: BanFormState, formData: FormData): Promise<BanFormState> {
  const ip = String(formData.get("ip") ?? "").trim();
  const reason = String(formData.get("reason") ?? "").trim();
  const duration = String(formData.get("duration") ?? "60");
  const values = { ip, reason, duration };

  const fieldErrors: BanFormState["fieldErrors"] = {};
  if (!IP_RE.test(ip)) fieldErrors.ip = "Saisissez une adresse IPv4 (ex. 192.168.137.25) ou IPv6.";
  else if (ip === (await requesterIp())) fieldErrors.ip = "C'est votre propre adresse : la bannir vous couperait l'accès.";
  if (reason.length < 3) fieldErrors.reason = "Indiquez un motif (3 caractères au moins) : il est inscrit dans l'audit.";
  if (!BAN_DURATIONS.some((d) => d.value === duration)) fieldErrors.duration = "Durée non proposée.";
  if (fieldErrors.ip || fieldErrors.reason || fieldErrors.duration) return { fieldErrors, values };

  const res = await authed<Ban>("/api/security/bans", {
    method: "POST",
    body: { ip, reason, duration_minutes: duration ? Number(duration) : null },
  });
  if (!res.ok) {
    if (res.kind === "validation") {
      // Adresse protégée (partagée par plusieurs clients) : message explicite du détecteur.
      if (typeof res.detail === "string") return { fieldErrors: { ip: res.detail }, values };
      return { fieldErrors: { ip: res.fieldErrors.ip, reason: res.fieldErrors.reason }, values };
    }
    if (unavailable(res.kind))
      return { message: "Le détecteur (liste des bans) est indisponible. Aucune adresse n'a été bannie ; réessayez.", values };
    if (res.kind === "forbidden") return { message: "Réservé au rôle administrateur.", values };
    return { message: res.message, values };
  }
  revalidatePath("/admin/security");
  return { ok: `${res.data.ip} est bannie${res.data.until ? "" : " de façon permanente"}.` };
}

export async function unbanIp(ip: string): Promise<RowActionState> {
  const res = await authed<{ unbanned: boolean }>(`/api/security/bans/${encodeURIComponent(ip)}`, { method: "DELETE" });
  if (!res.ok && res.kind !== "not_found") {
    return { message: unavailable(res.kind) ? "Détecteur indisponible, réessayez." : res.message };
  }
  revalidatePath("/admin/security");
  return {};
}

export async function unblockClient(client: string): Promise<RowActionState> {
  const res = await authed<{ unblocked: boolean }>(`/api/security/blocks?client=${encodeURIComponent(client)}`, {
    method: "DELETE",
  });
  if (!res.ok) return { message: unavailable(res.kind) ? "Détecteur indisponible, réessayez." : res.message };
  revalidatePath("/admin/security");
  return {};
}
