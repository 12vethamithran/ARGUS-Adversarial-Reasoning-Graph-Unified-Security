// ============================================================
// ARGUS — Finding knowledge base
// Supplies human-readable description / impact / remediation for
// every finding, keyed by OWASP / MITRE ref with a per-layer
// fallback. Works for both real-scan and mock findings.
// ============================================================
import type { Finding, SeverityLevel } from "./types";

export interface LayerMeta {
  id: number;
  name: string;
  short: string;
  domain: "Web" | "AI/LLM" | "Infrastructure" | "Identity";
  description: string;
  standard: string;
}

export const LAYER_META: Record<number, LayerMeta> = {
  1: { id: 1, name: "Web Surface", short: "Web", domain: "Web", standard: "OWASP Web Top 10",
       description: "External HTTP attack surface — security headers, CORS policy, CSP, TLS posture, exposed methods, and secrets leaking in responses." },
  2: { id: 2, name: "LLM Probe", short: "LLM", domain: "AI/LLM", standard: "OWASP LLM01/06/07:2025",
       description: "Direct and indirect prompt-injection testing, system-prompt leakage, jailbreaks, and unsafe tool exposure on the model endpoint." },
  3: { id: 3, name: "RAG Poisoning", short: "RAG", domain: "AI/LLM", standard: "OWASP LLM08:2025",
       description: "Retrieval corpus integrity — adversarial document injection, retrieval displacement, and hidden instructions embedded in indexed content." },
  4: { id: 4, name: "MCP / Agentic", short: "MCP", domain: "AI/LLM", standard: "OWASP Agentic Top 10",
       description: "Tool-calling and agent autonomy risks — confused-deputy, tool-call hijacking, excessive agency, and unsafe MCP server exposure." },
  5: { id: 5, name: "Network Recon", short: "Network", domain: "Infrastructure", standard: "MITRE ATT&CK T1046",
       description: "Internal topology mapping, reachable sensitive services, lateral-movement paths, and network-exposed inference endpoints." },
  6: { id: 6, name: "Supply Chain", short: "Supply", domain: "Infrastructure", standard: "OWASP A03:2025 / SkillJect",
       description: "Dependency and skill provenance — known-vulnerable packages, typosquats, and unvetted agent skill/plugin installation." },
  7: { id: 7, name: "Multi-Agent Propagation", short: "M-Agent", domain: "AI/LLM", standard: "MASpi",
       description: "Prompt-infection spread across an agent mesh — orchestrator compromise, trust-boundary failures, and worm-like propagation." },
  8: { id: 8, name: "Identity / OAuth", short: "Identity", domain: "Identity", standard: "MITRE ATLAS",
       description: "Session and token handling for MCP/OAuth — token interception, plaintext credentials, scope abuse, and session hijacking." },
};

interface KbEntry { description: string; impact: string; remediation: string; }

// Keyed by OWASP / MITRE reference.
const REF_KB: Record<string, KbEntry> = {
  // ── OWASP Web Top 10 (2025) ──────────────────────────────────────────────
  "A01:2025": {
    description: "Broken access control — authorization is not enforced server-side: force-browsing to privileged paths, IDOR, path traversal, CSRF, and SSRF (folded into this category in 2025).",
    impact: "An attacker reaches admin functionality, reads/modifies other users' objects, forges state-changing requests, or coerces the server into requests to internal hosts and cloud metadata.",
    remediation: "Deny by default and enforce per-object ownership checks server-side; use anti-CSRF tokens + SameSite; allow-list redirect/SSRF destinations and block private/link-local ranges.",
  },
  "A02:2025": {
    description: "Security misconfiguration — a hardening control (security header, CORS policy, HTTP method restriction) is missing or permissive, or a sensitive path/dotfile is exposed.",
    impact: "Weakens defense-in-depth, enabling clickjacking, cross-origin data theft, MIME sniffing, downgrade attacks, or disclosure of config/secret files.",
    remediation: "Apply a hardened baseline at the edge (CSP, HSTS, restrictive CORS), disable unneeded methods, and block access to dotfiles/admin endpoints.",
  },
  "A03:2025": {
    description: "Software supply chain failures — vulnerable/outdated or compromised components, typosquatted packages, unsigned dependencies, or unvetted skills/plugins (expands the 2021 'Vulnerable & Outdated Components').",
    impact: "Known exploits run directly against the component, and malicious/typosquatted packages can execute code at install or runtime.",
    remediation: "Maintain an SBOM, pin and hash dependencies, scan continuously (pip-audit/npm audit), and gate installs through an audited registry with signed artifacts.",
  },
  "A04:2025": {
    description: "Cryptographic failures — sensitive material (keys, tokens, credentials) is disclosed or weakly protected, including cleartext transport.",
    impact: "An attacker who recovers the secret or intercepts cleartext traffic can impersonate the service, decrypt data, or pivot into connected systems.",
    remediation: "Enforce TLS 1.2+ with HSTS, remove secrets from client-reachable responses, store credentials in a managed vault, and use strong current algorithms.",
  },
  "A05:2025": {
    description: "Injection — untrusted input is interpreted as code or query syntax (SQL, NoSQL, OS command, server-side template, or reflected into HTML/JS as XSS).",
    impact: "Database disclosure or modification, remote command/template execution, or script execution in victims' browsers — frequently a full-compromise primitive.",
    remediation: "Use parameterized queries / safe APIs, contextually output-encode all reflected data, sandbox template engines, and validate input against strict allow-lists.",
  },
  "A06:2025": {
    description: "Insecure design — missing or ineffective security controls at the design level rather than an implementation bug.",
    impact: "Whole classes of attack remain possible because the control was never designed in.",
    remediation: "Threat-model during design, use secure reference architectures, and add the missing control by design.",
  },
  "A07:2025": {
    description: "Authentication failures — credentials or sessions are weakly protected (password fields over HTTP, session cookies lacking Secure/HttpOnly/SameSite, fixation, missing MFA).",
    impact: "Session theft, credential interception, and account takeover without defeating any strong control.",
    remediation: "Serve auth over TLS only, set Secure/HttpOnly/SameSite, regenerate session IDs on login, enforce TTLs, and add MFA.",
  },
  "A08:2025": {
    description: "Software or data integrity failures — code/data consumed without integrity verification: missing Subresource Integrity (SRI), insecure deserialization, unsigned updates.",
    impact: "A compromised CDN or third party can inject arbitrary code that runs with the app's full privileges.",
    remediation: "Add SRI hashes to external resources, verify signatures, secure CI/CD, and pin third-party assets.",
  },
  "A09:2025": {
    description: "Security logging and alerting failures — insufficient logging/alerting lets attacks go undetected; verbose errors also leak internals.",
    impact: "Attacks proceed undetected and incident response is blinded; leaked traces also aid the attacker directly.",
    remediation: "Log auth/access/input-validation failures in a SIEM-consumable format, suppress verbose errors to clients, and alert on anomalies.",
  },
  "A10:2025": {
    description: "Mishandling of exceptional conditions (new in 2025) — uncaught exceptions, leaked stack traces, fail-open logic, or debug modes left enabled.",
    impact: "Leaked internals (paths, framework versions, queries) accelerate exploitation, and fail-open error paths can bypass security checks.",
    remediation: "Fail closed, return generic error pages, disable debug in production, and explicitly handle and test exceptional paths.",
  },
  "LLM01:2025": {
    description: "Prompt injection — untrusted input overrides the model's instructions, directly or via retrieved/embedded content.",
    impact: "The model can be steered to leak data, ignore guardrails, or invoke tools on the attacker's behalf.",
    remediation: "Separate system and user channels, constrain outputs to schemas, and treat all model output as untrusted before acting on it.",
  },
  "LLM02:2025": {
    description: "Insecure output handling — model output is consumed downstream (rendered as HTML/JS, used in a shell, or as SQL) without treating it as untrusted.",
    impact: "An injected response becomes stored/reflected XSS, command injection, or SQLi in the consuming system — the model is turned into an injection vector.",
    remediation: "Encode/sanitize model output for its sink, never eval or shell-exec it, and apply the same output-encoding rules you would to any untrusted user input.",
  },
  "LLM06:2025": {
    description: "Excessive agency — the model is granted tools or permissions broader than its task requires.",
    impact: "A single injection can be amplified into real-world actions (writes, deletes, network calls) — the confused-deputy problem.",
    remediation: "Apply least-privilege to every tool, require human approval for high-impact actions, and sandbox tool execution.",
  },
  "LLM07:2025": {
    description: "System-prompt leakage — the model can be coaxed into revealing its hidden instructions or configuration.",
    impact: "Exposes guardrail logic and secrets in the prompt, making downstream jailbreaks and bypasses far easier.",
    remediation: "Never place secrets in prompts, add leakage detection, and assume the system prompt is public when designing controls.",
  },
  "LLM08:2025": {
    description: "Vector / RAG weakness — the retrieval corpus can be poisoned so adversarial documents displace legitimate results.",
    impact: "Poisoned context is fed to the model as 'trusted', enabling stealthy misinformation or indirect prompt injection at scale.",
    remediation: "Sign and validate corpus documents, detect outlier embeddings, and isolate untrusted sources from the production index.",
  },
  "LLM09:2025": {
    description: "Overreliance / exposed inference — an LLM endpoint is reachable on the network without adequate controls.",
    impact: "Direct, unauthenticated model access enables abuse, data exfiltration, and resource exhaustion.",
    remediation: "Place inference behind authentication and rate limiting, and restrict network reachability to known callers.",
  },
  "OWASP-AGT-01": {
    description: "Agent tool-call hijack / confused deputy — an agent is induced to invoke a privileged tool using attacker-controlled arguments.",
    impact: "Turns a text-level injection into concrete privileged actions inside the environment.",
    remediation: "Validate and constrain tool arguments, enforce per-tool authorization, and require confirmation for sensitive calls.",
  },
  "OWASP-AGT-03": {
    description: "Missing inter-agent trust boundary — messages between agents are not authenticated or verified.",
    impact: "A compromised agent can forge instructions that peers accept, enabling lateral propagation across the mesh.",
    remediation: "Sign inter-agent messages, verify provenance, and isolate agents with distinct, least-privilege identities.",
  },
  "OWASP-AGT-05": {
    description: "Excessive MCP tool exposure — the MCP server advertises a broad set of callable tools.",
    impact: "Expands the attack surface an injected prompt can reach, increasing blast radius.",
    remediation: "Expose only the tools each agent needs, scope them per session, and audit the advertised tool list.",
  },
  "OWASP-AGT-07": {
    description: "SkillJect / unvetted skill installation — the agent ecosystem allows installing third-party skills without review.",
    impact: "A malicious skill can run code, exfiltrate data, or persist inside the agent runtime.",
    remediation: "Require signed/reviewed skills, maintain an allow-list, and sandbox skill execution.",
  },
  "OWASP-AGT-09": {
    description: "Multi-agent prompt infection — an injected instruction self-propagates between cooperating agents.",
    impact: "Worm-like spread can compromise an entire agent mesh from a single entry point.",
    remediation: "Add message provenance checks, content sanitization at agent boundaries, and propagation rate limits / circuit breakers.",
  },
  "T1046": {
    description: "Network service scanning — internal hosts and services are discoverable and reachable from the entry tier.",
    impact: "Reveals lateral-movement targets such as databases and inference hosts that should be segmented.",
    remediation: "Segment networks, restrict east-west traffic with firewall policy, and remove unnecessary service exposure.",
  },
  "T1021": {
    description: "Lateral movement — a reachable path exists from a web-facing host to a sensitive internal system.",
    impact: "An attacker who lands on the web tier can pivot directly to high-value internal assets.",
    remediation: "Enforce network segmentation and least-privilege service accounts; monitor and alert on cross-tier connections.",
  },
  "T1190": {
    description: "Exploit public-facing application — a reachable web vulnerability (injection, broken access control, open redirect) is exercised against the entry tier.",
    impact: "Initial access or data disclosure from the internet-facing surface, often the first hop of a kill chain.",
    remediation: "Patch and harden the application, validate all input server-side, and place a WAF / rate limiting in front of exposed endpoints.",
  },
  "T1083": {
    description: "File and directory discovery via path traversal / LFI — '../' sequences escape the intended directory to read arbitrary files.",
    impact: "Disclosure of configuration, source, or credential files (e.g. /etc/passwd), enabling deeper compromise.",
    remediation: "Canonicalize and confine file paths to a safe root, reject traversal sequences, and avoid passing user input to filesystem APIs.",
  },
  "T1221": {
    description: "Template injection (SSTI) — user input is evaluated by a server-side template engine.",
    impact: "Expression evaluation that frequently escalates to remote code execution on the server.",
    remediation: "Never render user input as a template; use sandboxed/logic-less templates and pass data as bound variables only.",
  },
  "T1539": {
    description: "Steal web session / access another user's object (IDOR) — predictable object references are not owner-checked.",
    impact: "Horizontal/vertical privilege escalation: reading or modifying objects belonging to other users.",
    remediation: "Enforce per-object authorization on every request and use unpredictable, server-mapped identifiers.",
  },
  "T1090": {
    description: "Proxy / SSRF — the server is coerced into making requests to attacker-chosen internal destinations.",
    impact: "Reaches internal-only services and cloud metadata endpoints, often yielding credentials or a network pivot.",
    remediation: "Validate and allow-list outbound destinations, block metadata and private IP ranges, and isolate egress.",
  },
  "T1592": {
    description: "Gather victim host information — version banners and verbose errors disclose components and internals.",
    impact: "Fingerprinting that lets an attacker target known CVEs and tailor payloads.",
    remediation: "Suppress version banners and stack traces, and return generic error responses.",
  },
  "T1195": {
    description: "Supply-chain compromise — externally loaded code/resources lack integrity verification (missing SRI).",
    impact: "A compromised third party can inject code that executes with the application's privileges.",
    remediation: "Add Subresource Integrity hashes, verify signatures, and pin third-party dependencies.",
  },
  "AML.T0012": {
    description: "Valid credential / token abuse — a session token or credential is exposed (e.g. in a URL or plaintext).",
    impact: "Enables session hijacking and persistent unauthorized access without triggering authentication controls.",
    remediation: "Move tokens out of URLs into secure storage, shorten lifetimes, bind to client, and rotate on exposure.",
  },
  "AML.T0019": {
    description: "ML supply-chain compromise — a poisoned dependency or skill enters the build/runtime.",
    impact: "Code execution and data theft at install or runtime, often bypassing application-level controls.",
    remediation: "Verify provenance/signatures, pin and hash artifacts, and scan dependencies continuously.",
  },
  "AML.T0020": {
    description: "Training/retrieval data poisoning — adversarial content is injected into data the model trusts.",
    impact: "Biases or hijacks model behavior at inference time in ways that are hard to detect post-hoc.",
    remediation: "Validate and sign data sources, detect anomalous embeddings, and quarantine untrusted inputs.",
  },
  "AML.T0043": {
    description: "Crafted adversarial input that exploits tool-using model behavior (confused deputy via prompt).",
    impact: "Drives unintended privileged tool invocations through the model.",
    remediation: "Constrain tool schemas, validate arguments, and require approval for sensitive operations.",
  },
  "AML.T0048": {
    description: "Societal/system-level impact — full orchestrator or control-plane compromise of an agent system.",
    impact: "Attacker gains control over the agent mesh's decision-making and downstream actions.",
    remediation: "Harden the orchestrator, isolate its identity, and add kill-switch / circuit-breaker controls.",
  },
  "AML.T0051": {
    description: "LLM prompt injection (MITRE ATLAS) — input manipulates the model into attacker-chosen behavior.",
    impact: "Guardrail bypass, data leakage, or unauthorized tool use originating from untrusted text.",
    remediation: "Channel separation, output validation, and treating model output as untrusted before acting.",
  },
  "AML.T0054": {
    description: "Hidden instruction injection — instructions concealed in content (e.g. HTML comments) reach the model.",
    impact: "Stealthy indirect prompt injection that evades casual review of the corpus.",
    remediation: "Strip/normalize markup before indexing, and scan corpus content for hidden directives.",
  },
};

// Per-layer fallback when no ref-specific entry exists.
function layerFallback(layer: number): KbEntry {
  const m = LAYER_META[layer];
  return {
    description: m ? m.description : "Security finding identified during analysis.",
    impact: m ? `Affects the ${m.domain} attack surface and may contribute to a larger attack chain.`
              : "May contribute to a larger attack chain.",
    remediation: "Review the evidence, validate exploitability, and apply the relevant hardening control for this layer.",
  };
}

export interface FindingDetail {
  description: string;
  impact: string;
  remediation: string;
  refs: string[];
  layerName: string;
  domain: string;
}

export function describeFinding(f: Finding): FindingDetail {
  const refs = [f.owasp_ref, f.mitre_ref].filter(Boolean) as string[];
  const entry =
    (f.owasp_ref && REF_KB[f.owasp_ref]) ||
    (f.mitre_ref && REF_KB[f.mitre_ref]) ||
    layerFallback(f.layer);
  const m = LAYER_META[f.layer];
  return {
    ...entry,
    refs,
    layerName: m?.name ?? `Layer ${f.layer}`,
    domain: m?.domain ?? "—",
  };
}

export const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

export const SEVERITY_WEIGHT: Record<SeverityLevel, number> = {
  info: 0.1, low: 0.3, medium: 0.55, high: 0.78, critical: 1.0,
};

/** 0-100 composite risk score from a set of findings. */
export function riskScore(findings: Finding[]): number {
  if (!findings.length) return 0;
  const top = [...findings].sort(
    (a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity],
  );
  const maxSev = SEVERITY_WEIGHT[top[0].severity];
  const exploitable = findings.filter((f) => f.exploitable).length;
  const breadth = new Set(findings.map((f) => f.layer)).size;
  const score = maxSev * 60 + Math.min(exploitable * 6, 24) + Math.min(breadth * 2, 16);
  return Math.min(100, Math.round(score));
}

export function evidenceEntries(f: Finding): [string, string][] {
  return Object.entries(f.evidence ?? {})
    .filter(([k]) => k !== "mock")
    .map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)]);
}
