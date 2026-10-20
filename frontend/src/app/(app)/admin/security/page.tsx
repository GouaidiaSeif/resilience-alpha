import { BrainCircuit, ShieldAlert, ShieldCheck, UserRound, type LucideIcon } from "lucide-react";
import type { Metadata } from "next";
import { headers } from "next/headers";
import { Suspense } from "react";

import { Time } from "@/components/ui/data";
import { PageHeader } from "@/components/ui/page-header";
import { Panel } from "@/components/ui/panel";
import { RetryButton } from "@/components/ui/retry-button";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/states";
import { Table, TD, TH, THead, TR } from "@/components/ui/table";
import { cn } from "@/lib/cn";
import { getBans, getMlBlocks } from "@/lib/data";
import { serviceLabel } from "@/lib/messages";
import type { BanSource } from "@/lib/types";

import { BanForm } from "./ban-form";
import { RowAction } from "./row-action";

export const metadata: Metadata = { title: "Sécurité" };

const ORIGINS: Record<BanSource, { label: string; icon: LucideIcon; cls: string }> = {
  manual: { label: "Manuel", icon: UserRound, cls: "border-border bg-surface-subtle text-fg-muted" },
  waf: { label: "WAF", icon: ShieldAlert, cls: "border-transparent bg-warning-tint text-warning" },
  ml: { label: "Modèle ML", icon: BrainCircuit, cls: "border-transparent bg-primary-tint text-primary" },
};

function OriginBadge({ source }: { source: BanSource }) {
  const o = ORIGINS[source] ?? ORIGINS.manual;
  const Icon = o.icon;
  return (
    <span className={cn("inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-[12.5px] leading-none font-medium whitespace-nowrap", o.cls)}>
      <Icon aria-hidden="true" className="size-3.5" strokeWidth={2.25} />
      {o.label}
    </span>
  );
}

/** Temps restant lisible : « 52 min », « 23 h 05 » (jusqu'à 48 h), puis « 6 j 23 h ». */
function remaining(seconds: number): string {
  if (seconds < 60) return "< 1 min";
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${String(m % 60).padStart(2, "0")}`;
  return `${Math.floor(h / 24)} j ${h % 24} h`;
}

const iso = (epoch: number) => new Date(epoch * 1000).toISOString();

async function BansTable() {
  const bans = await getBans();
  if (!bans.ok) return <ErrorState error={bans} service="detector" />;
  if (bans.data.length === 0) {
    return (
      <EmptyState icon={ShieldCheck} title="Aucune adresse bannie">
        Les adresses bannies par un administrateur, par le WAF ou par le modèle ML apparaîtront ici.
      </EmptyState>
    );
  }
  return (
    <Table caption="Adresses IP bannies, de la plus récente à la plus ancienne">
      <THead>
        <tr>
          <TH>Adresse IP</TH>
          <TH>Origine</TH>
          <TH className="hidden md:table-cell">Motif</TH>
          <TH className="hidden lg:table-cell">Depuis</TH>
          <TH>Fin</TH>
          <TH className="hidden xl:table-cell">Par</TH>
          <TH className="text-right">
            <span className="sr-only">Action</span>
          </TH>
        </tr>
      </THead>
      <tbody>
        {bans.data.map((b) => (
          <TR key={b.ip} className="align-top">
            <TD className="font-mono text-[13px] whitespace-nowrap">{b.ip}</TD>
            <TD>
              <OriginBadge source={b.source} />
            </TD>
            <TD className="hidden max-w-80 text-fg-muted md:table-cell">{b.reason}</TD>
            <TD className="hidden lg:table-cell">
              <Time iso={iso(b.created_at)} />
            </TD>
            <TD className="tabular whitespace-nowrap">
              {b.remaining_seconds === null ? <span className="font-medium">Permanent</span> : `dans ${remaining(b.remaining_seconds)}`}
            </TD>
            <TD className="hidden text-fg-muted xl:table-cell">{b.by ?? "Automatique"}</TD>
            <TD className="text-right">
              <RowAction kind="unban" target={b.ip} label={b.ip} />
            </TD>
          </TR>
        ))}
      </tbody>
    </Table>
  );
}

async function BlocksTable() {
  const blocks = await getMlBlocks();
  if (!blocks.ok) return <ErrorState error={blocks} service="detector" />;
  if (blocks.data.length === 0) {
    return (
      <EmptyState icon={BrainCircuit} title="Aucun client bloqué par le modèle">
        Un client jugé anormal deux évaluations de suite (environ 10 s) est bloqué 10 min ; son adresse est aussi bannie
        quand elle n&apos;est pas partagée.
      </EmptyState>
    );
  }
  return (
    <Table caption="Clients bloqués temporairement par le modèle ML">
      <THead>
        <tr>
          <TH>Adresse IP</TH>
          <TH className="hidden md:table-cell">Agent utilisateur</TH>
          <TH>Service visé</TH>
          <TH className="hidden lg:table-cell text-right">Score</TH>
          <TH>Fin</TH>
          <TH className="text-right">
            <span className="sr-only">Action</span>
          </TH>
        </tr>
      </THead>
      <tbody>
        {blocks.data.map((b) => {
          const [ip, ...ua] = b.client.split("|");
          return (
            <TR key={b.client} className="align-top">
              <TD className="font-mono text-[13px] whitespace-nowrap">{ip}</TD>
              <TD className="hidden max-w-80 break-all font-mono text-[12px] text-fg-muted md:table-cell">{ua.join("|") || "—"}</TD>
              <TD className="whitespace-nowrap">{serviceLabel(b.service)}</TD>
              <TD className="tabular hidden text-right text-fg-muted lg:table-cell">{b.score.toFixed(3)}</TD>
              <TD className="tabular whitespace-nowrap">dans {remaining(b.remaining_seconds)}</TD>
              <TD className="text-right">
                <RowAction kind="unblock" target={b.client} label={ip} />
              </TD>
            </TR>
          );
        })}
      </tbody>
    </Table>
  );
}

export default async function SecurityPage() {
  const requester = (await headers()).get("x-forwarded-for")?.split(",")[0]?.trim() || null;
  return (
    <>
      <PageHeader
        eyebrow="Administration · sécurité"
        title="Sécurité"
        description="Liste des bans appliquée par le WAF à chaque requête, interface comprise : une adresse bannie reçoit 403 partout. Bans manuels, automatiques (WAF) et décidés par le modèle ML."
        actions={<RetryButton label="Actualiser" />}
      />
      <div className="flex flex-col gap-6">
        <div className="grid gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <Panel title="Bannir une adresse IP">
            <BanForm requester={requester} />
          </Panel>
          <Panel title="Comment une adresse est bannie">
            <ul className="flex flex-col gap-4 text-fg-muted">
              <li className="flex gap-3">
                <OriginBadge source="waf" />
                <span>Après 5 requêtes bloquées par le pare-feu applicatif (OWASP CRS) en 2 min : 1 h.</span>
              </li>
              <li className="flex gap-3">
                <OriginBadge source="ml" />
                <span>Quand le modèle bloque un client pour trafic anormal : 10 min.</span>
              </li>
              <li className="flex gap-3">
                <OriginBadge source="manual" />
                <span>Par un administrateur, depuis cette page : durée choisie ou permanent.</span>
              </li>
            </ul>
            <p className="mt-5 border-t border-border pt-4 text-[13px] leading-4.5 text-fg-subtle">
              Jamais bannies : les adresses partagées par plusieurs clients (hôte Docker sans relais d&apos;IP réelle, front,
              WAF). Chaque ban et chaque levée sont inscrits dans le journal d&apos;audit.
            </p>
          </Panel>
        </div>
        <Panel title="Adresses IP bannies" flush>
          <Suspense fallback={<TableSkeleton rows={3} label="Chargement des bans" />}>
            <BansTable />
          </Suspense>
        </Panel>
        <Panel
          title="Clients bloqués par le modèle ML"
          description="Blocage par client (adresse et agent utilisateur), en plus du ban de l'adresse."
          flush
        >
          <Suspense fallback={<TableSkeleton rows={2} label="Chargement des blocages" />}>
            <BlocksTable />
          </Suspense>
        </Panel>
      </div>
    </>
  );
}
