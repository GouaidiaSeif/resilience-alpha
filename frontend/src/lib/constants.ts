// Devises proposées à l'ouverture d'un compte (la plateforme accepte tout code ISO à 3 lettres).
export const CURRENCIES = ["EUR", "USD", "GBP", "CHF"] as const;

/** Durées proposées, en minutes ; vide = permanent. */
export const BAN_DURATIONS = [
  { value: "60", label: "1 heure" },
  { value: "1440", label: "24 heures" },
  { value: "10080", label: "7 jours" },
  { value: "43200", label: "30 jours" },
  { value: "", label: "Permanent" },
] as const;
