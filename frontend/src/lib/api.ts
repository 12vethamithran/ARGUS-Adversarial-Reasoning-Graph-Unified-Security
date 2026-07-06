// ============================================================
// ARGUS — Report API helpers
// ------------------------------------------------------------
// The live analysis stream is driven by store/eventStream.ts; this
// module only exposes the report export endpoints used by the UI.
// ============================================================

const BASE = import.meta.env.VITE_API_URL ?? "";

/** Open the HTML report in a new tab. */
export function openHtmlReport(sessionId: string): void {
  window.open(`${BASE}/api/reports/${sessionId}/html`, "_blank");
}

/** Trigger full analyst PDF report download. */
export async function downloadPdfReport(sessionId: string): Promise<void> {
  const response = await fetch(`${BASE}/api/reports/${sessionId}/pdf`);
  if (!response.ok) {
    let detail = `PDF download failed (${response.status})`;
    try {
      const body = await response.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      const text = await response.text();
      if (text) detail = text.slice(0, 240);
    }
    throw new Error(detail);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `argus-analyst-report-${sessionId.slice(0, 8)}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Trigger STIX 2.1 JSON download. */
export function downloadStixReport(sessionId: string): void {
  const a = document.createElement("a");
  a.href = `${BASE}/api/reports/${sessionId}/stix`;
  a.download = `argus-stix-${sessionId.slice(0, 8)}.json`;
  a.click();
}
