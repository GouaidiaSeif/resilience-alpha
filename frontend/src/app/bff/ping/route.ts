import { NextResponse } from "next/server";

// Contrôle de santé du conteneur : le serveur Next répond, sans appeler la passerelle.
export function GET() {
  return NextResponse.json({ status: "ok" });
}
