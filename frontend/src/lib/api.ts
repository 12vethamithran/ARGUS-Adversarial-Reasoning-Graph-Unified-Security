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
export function downloadPdfReport(sessionId: string): void {
  const a = document.createElement("a");
  a.href = `${BASE}/api/reports/${sessionId}/pdf`;
  a.download = `argus-analyst-report-${sessionId.slice(0, 8)}.pdf`;
  a.click();
}

/** Trigger STIX 2.1 JSON download. */
export function downloadStixReport(sessionId: string): void {
  const a = document.createElement("a");
  a.href = `${BASE}/api/reports/${sessionId}/stix`;
  a.download = `argus-stix-${sessionId.slice(0, 8)}.json`;
  a.click();
}
