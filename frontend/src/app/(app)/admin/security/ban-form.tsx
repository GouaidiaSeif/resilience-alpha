"use client";

import { Ban } from "lucide-react";
import { useActionState } from "react";

import { banIp, type BanFormState } from "@/actions/security";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { BAN_DURATIONS } from "@/lib/constants";

export function BanForm({ requester }: { requester: string | null }) {
  const [state, action, pending] = useActionState<BanFormState, FormData>(banIp, {});
  // Après un ban réussi, le formulaire repart vide (clé changée) ; en cas d'erreur, il garde la saisie.
  const values = state.ok ? undefined : state.values;
  return (
    <form action={action} className="flex flex-col gap-5" noValidate key={state.ok ?? "form"}>
      {state.ok ? (
        <Alert tone="success" title="Adresse bannie" role="status">
          {state.ok} Toutes ses requêtes reçoivent désormais 403, interface comprise.
        </Alert>
      ) : null}
      {state.message ? (
        <Alert tone="danger" title="Adresse non bannie" role="alert">
          {state.message}
        </Alert>
      ) : null}
      <div className="grid gap-5 sm:grid-cols-[minmax(0,1fr)_12rem]">
        <Field
          id="ip"
          label="Adresse IP"
          helper={requester ? `Votre adresse vue par la plateforme : ${requester}` : undefined}
          error={state.fieldErrors?.ip}
        >
          {(aria) => (
            <Input {...aria} name="ip" autoComplete="off" spellCheck={false} placeholder="192.168.137.25" defaultValue={values?.ip ?? ""} className="font-mono" />
          )}
        </Field>
        <Field id="duration" label="Durée" error={state.fieldErrors?.duration}>
          {(aria) => (
            <Select {...aria} name="duration" defaultValue={values?.duration ?? "60"}>
              {BAN_DURATIONS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <Field id="reason" label="Motif" helper="Inscrit dans la piste d'audit avec votre nom." error={state.fieldErrors?.reason}>
        {(aria) => <Input {...aria} name="reason" maxLength={200} autoComplete="off" placeholder="Balayage depuis le poste de test" defaultValue={values?.reason ?? ""} />}
      </Field>
      <div className="border-t border-border pt-5">
        <Button type="submit" variant="danger" loading={pending} loadingLabel="Bannissement…">
          <Ban aria-hidden="true" />
          Bannir l&apos;adresse
        </Button>
      </div>
    </form>
  );
}
