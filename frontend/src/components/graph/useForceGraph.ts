import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { Finding, Chain } from "../../lib/types";

/** Read a theme CSS variable (space-separated RGB channels) as an rgb() string. */
function cssColor(name: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v ? `rgb(${v})` : fallback;
}

function nodeColors() {
  return {
    discovered: cssColor("--node-discovered", "#546e7a"),
    probing: cssColor("--node-probing", "#ffb300"),
    exploitable: cssColor("--node-exploitable", "#ff3d57"),
    chained: cssColor("--node-chained", "#00e5ff"),
  } as Record<string, string>;
}

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  layer: number;
  state: Finding["node_state"];
  severity: string;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  chained: boolean;
}

export interface GraphControls {
  zoomIn: () => void;
  zoomOut: () => void;
  reset: () => void;
}

export function useForceGraph(
  svgRef: React.RefObject<SVGSVGElement>,
  findings: Record<string, Finding>,
  chains: Chain[],
  onSelect?: (id: string | null) => void,
  controlsRef?: React.MutableRefObject<GraphControls | null>,
) {
  const simRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    const { width, height } = svgRef.current.getBoundingClientRect();

    const NODE_COLOR = nodeColors();
    const CHAINED = NODE_COLOR.chained;
    const LINE = cssColor("--border", "#2a3040");
    const LABEL = cssColor("--text-secondary", "#90a4ae");

    const nodes: GraphNode[] = Object.values(findings).map((f) => ({
      id: f.id,
      label: f.title.length > 30 ? f.title.slice(0, 28) + "…" : f.title,
      layer: f.layer,
      state: f.node_state,
      severity: f.severity,
    }));

    // Strong (chained) links between consecutive chain steps.
    const links: GraphLink[] = [];
    chains.forEach((c) => {
      for (let i = 0; i < c.steps.length - 1; i++) {
        const src = c.steps[i], tgt = c.steps[i + 1];
        if (findings[src] && findings[tgt]) links.push({ source: src, target: tgt, chained: true });
      }
    });
    // Faint sibling links between findings on the same layer so the graph reads
    // as a connected map rather than scattered dots.
    const byLayer: Record<number, GraphNode[]> = {};
    nodes.forEach((n) => (byLayer[n.layer] ??= []).push(n));
    Object.values(byLayer).forEach((sibs) => {
      for (let i = 0; i < sibs.length - 1; i++)
        links.push({ source: sibs[i].id, target: sibs[i + 1].id, chained: false });
    });

    // adjacency for hover highlight
    const neighbors = new Map<string, Set<string>>();
    nodes.forEach((n) => neighbors.set(n.id, new Set([n.id])));
    links.forEach((l) => {
      const s = typeof l.source === "string" ? l.source : (l.source as GraphNode).id;
      const t = typeof l.target === "string" ? l.target : (l.target as GraphNode).id;
      neighbors.get(s)?.add(t);
      neighbors.get(t)?.add(s);
    });

    svg.selectAll("*").remove();
    const g = svg.append("g");

    const zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.3, 3]).on("zoom", (e) => {
      g.attr("transform", e.transform);
    });
    svg.call(zoom);
    // click empty space → deselect
    svg.on("click", () => onSelect?.(null));

    if (controlsRef) {
      controlsRef.current = {
        zoomIn: () => svg.transition().duration(250).call(zoom.scaleBy, 1.4),
        zoomOut: () => svg.transition().duration(250).call(zoom.scaleBy, 1 / 1.4),
        reset: () => svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity),
      };
    }

    // Arrowhead
    svg.append("defs").append("marker")
      .attr("id", "arrow-chained").attr("viewBox", "0 -5 10 10")
      .attr("refX", 20).attr("refY", 0).attr("markerWidth", 6).attr("markerHeight", 6)
      .attr("orient", "auto").append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", CHAINED);

    const link = g.append("g").selectAll("line").data(links).join("line")
      .attr("stroke", (d) => (d.chained ? CHAINED : LINE))
      .attr("stroke-width", (d) => (d.chained ? 2 : 1))
      .attr("stroke-opacity", (d) => (d.chained ? 0.85 : 0.25))
      .attr("stroke-dasharray", (d) => (d.chained ? null : "2,3"))
      .attr("marker-end", (d) => (d.chained ? "url(#arrow-chained)" : null));

    const node = g.append("g").selectAll<SVGGElement, GraphNode>("g").data(nodes).join("g")
      .attr("cursor", "pointer");

    const circle = node.append("circle")
      .attr("r", (d) => (d.state === "chained" ? 11 : 8))
      .attr("fill", (d) => NODE_COLOR[d.state] ?? NODE_COLOR.discovered)
      .attr("stroke", (d) => (d.state === "chained" ? CHAINED : "rgba(127,127,127,0.25)"))
      .attr("stroke-width", (d) => (d.state === "chained" ? 2 : 1));

    node.append("text").text((d) => `L${d.layer}`)
      .attr("text-anchor", "middle").attr("dominant-baseline", "central")
      .attr("fill", "#ffffff").attr("font-size", "7px")
      .attr("font-family", "JetBrains Mono, monospace").attr("font-weight", "bold")
      .attr("pointer-events", "none");

    const labels = node.append("text").text((d) => d.label)
      .attr("text-anchor", "middle").attr("y", 20)
      .attr("fill", LABEL).attr("font-size", "9px")
      .attr("font-family", "Inter, sans-serif").attr("pointer-events", "none");

    // ── Interactivity ────────────────────────────────────────────────────────
    node.on("click", (event, d) => { event.stopPropagation(); onSelect?.(d.id); });

    node.on("mouseover", (_e, d) => {
      const near = neighbors.get(d.id) ?? new Set([d.id]);
      node.transition().duration(120).style("opacity", (n) => (near.has(n.id) ? 1 : 0.15));
      link.transition().duration(120).style("opacity", (l) => {
        const s = (l.source as GraphNode).id, t = (l.target as GraphNode).id;
        return s === d.id || t === d.id ? 1 : 0.05;
      });
      labels.filter((n) => n.id === d.id).attr("font-weight", "bold");
    }).on("mouseout", () => {
      node.transition().duration(120).style("opacity", 1);
      link.transition().duration(120).style("opacity", (l: any) => (l.chained ? 0.85 : 0.25));
      labels.attr("font-weight", "normal");
    });

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink<GraphNode, GraphLink>(links).id((d) => d.id).distance((l) => (l.chained ? 110 : 60)))
      .force("charge", d3.forceManyBody().strength(-220))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(32))
      .on("tick", () => {
        link.attr("x1", (d) => (d.source as GraphNode).x!).attr("y1", (d) => (d.source as GraphNode).y!)
            .attr("x2", (d) => (d.target as GraphNode).x!).attr("y2", (d) => (d.target as GraphNode).y!);
        node.attr("transform", (d) => `translate(${d.x},${d.y})`);
      });
    simRef.current = sim;

    // Drag
    const drag = d3.drag<SVGGElement, GraphNode>()
      .on("start", (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; });
    node.call(drag);
    void circle;

    return () => { sim.stop(); };
  }, [findings, chains, onSelect]);
}
