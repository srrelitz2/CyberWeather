import { useEffect, useMemo, useRef } from "react";
import * as d3 from "d3";

const COLORS = {
  Ip: "#2f6f8f",
  Cve: "#b4532a",
  Tag: "#2a6b45",
  Country: "#8a6232",
  Organization: "#5c4d7a",
  Ja3: "#1d6f6d",
  Kev: "#8f2d2d",
  Indicator: "#3f3c37",
  Event: "#8d6b2f",
  Asn: "#5e6a74",
  Infrastructure: "#3f5c4a",
  Malware: "#7a3e3e",
  Tool: "#46586a",
  Identity: "#6a5878",
  AttackPattern: "#6e4b32",
  StixObject: "#6b7280",
  Meta: "#9aa0a6",
};

export default function Graph({ data, hops, onHops, focus, onFocus, pins, onPin }) {
  const wrapRef = useRef(null);
  const canvasRef = useRef(null);
  const stateRef = useRef(null);

  const summary = useMemo(() => {
    const counts = {};
    for (const node of data?.nodes || []) counts[node.kind] = (counts[node.kind] || 0) + 1;
    return counts;
  }, [data]);

  const pinsRef = useRef(pins);
  pinsRef.current = pins;

  useEffect(() => {
    const wrap = wrapRef.current;
    const canvas = canvasRef.current;
    if (!wrap || !canvas || !data) return undefined;
    const context = canvas.getContext("2d");
    const nodes = data.nodes.map((node) => {
      const pin = pinsRef.current[node.id];
      return pin ? { ...node, fx: pin.fx, fy: pin.fy } : { ...node };
    });
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const links = data.links
      .filter((link) => byId.has(link.source) && byId.has(link.target))
      .map((link) => ({ ...link }));
    const width = wrap.clientWidth || 800;
    const height = wrap.clientHeight || 560;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);

    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((node) => node.id).distance(nodes.length > 400 ? 28 : 48))
      .force("charge", d3.forceManyBody().strength(nodes.length > 400 ? -18 : -40))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide(nodes.length > 400 ? 6 : 10));

    const zoom = d3.zoom().scaleExtent([0.2, 4]).filter((event) => event.type === "wheel" || event.type === "dblclick").on("zoom", (event) => {
      state.transform = event.transform;
      draw();
    });
    const selection = d3.select(canvas);
    selection.call(zoom);
    const state = { transform: d3.zoomIdentity, hover: null, moved: false };
    stateRef.current = state;

    function nodeRadius(node) {
      if (node.id === focus) return 8;
      if (node.kind === "Ip") return node.trio ? 5 : 3.5;
      return 6;
    }

    function draw() {
      context.save();
      context.clearRect(0, 0, width, height);
      context.translate(state.transform.x, state.transform.y);
      context.scale(state.transform.k, state.transform.k);
      context.beginPath();
      context.strokeStyle = "rgba(40, 54, 68, 0.28)";
      context.lineWidth = 1;
      for (const link of links) {
        const source = typeof link.source === "object" ? link.source : byId.get(link.source);
        const target = typeof link.target === "object" ? link.target : byId.get(link.target);
        if (!source || !target) continue;
        context.moveTo(source.x, source.y);
        context.lineTo(target.x, target.y);
      }
      context.stroke();
      for (const node of nodes) {
        const radius = nodeRadius(node);
        context.beginPath();
        context.fillStyle = node.trio ? "#c9841a" : COLORS[node.kind] || "#6b7280";
        context.arc(node.x, node.y, radius, 0, Math.PI * 2);
        context.fill();
        if (node.id === focus || node.fx != null) {
          context.lineWidth = node.id === focus ? 2 : 1.25;
          context.strokeStyle = node.id === focus ? "#1c1915" : "#8a6232";
          context.stroke();
        }
        const showLabel =
          nodes.length < 80 ||
          node.id === focus ||
          node.fx != null ||
          node.id === state.hover ||
          node.trio ||
          node.kind === "Kev" ||
          node.kind === "Event";
        if (showLabel && node.kind !== "Tag") {
          context.font = "11px Palatino, Palatino Linotype, serif";
          context.fillStyle = "#1c1915";
          context.fillText(node.label, node.x + radius + 3, node.y + 3);
        }
      }
      context.restore();
    }

    simulation.on("tick", draw);

    function point(event) {
      const rect = canvas.getBoundingClientRect();
      const transformed = state.transform.invert([event.clientX - rect.left, event.clientY - rect.top]);
      return transformed;
    }

    function hit(event) {
      const [x, y] = point(event);
      let found = null;
      let best = 14;
      for (const node of nodes) {
        const distance = Math.hypot(node.x - x, node.y - y);
        if (distance < best) {
          best = distance;
          found = node;
        }
      }
      return found;
    }

    const drag = d3
      .drag()
      .subject((event) => {
        const node = hit(event.sourceEvent);
        return node || null;
      })
      .on("start", (event) => {
        state.moved = false;
        if (!event.active) simulation.alphaTarget(0.25).restart();
        if (event.subject) {
          event.subject.fx = event.subject.x;
          event.subject.fy = event.subject.y;
        }
      })
      .on("drag", (event) => {
        state.moved = true;
        if (!event.subject) return;
        const [x, y] = point(event.sourceEvent);
        event.subject.fx = x;
        event.subject.fy = y;
      })
      .on("end", (event) => {
        if (!event.active) simulation.alphaTarget(0);
        if (event.subject && state.moved) {
          onPin(event.subject.id, { fx: event.subject.fx, fy: event.subject.fy });
        }
      });

    selection.call(drag);
    selection.on("mousemove.graph", (event) => {
      const node = hit(event);
      state.hover = node ? node.id : null;
      canvas.style.cursor = node ? "pointer" : "grab";
      draw();
    });
    selection.on("click.graph", (event) => {
      if (state.moved) {
        state.moved = false;
        return;
      }
      const node = hit(event);
      if (node && node.id !== focus) onFocus(node.id);
    });

    return () => {
      simulation.stop();
      selection.on(".zoom", null);
      selection.on(".drag", null);
      selection.on(".graph", null);
    };
  }, [data, focus, onFocus, onPin]);

  const focusNode = data?.nodes?.find((node) => node.id === focus);
  const pinned = Boolean(pins[focus]);

  return (
    <section className="panel graph-panel">
      <header className="panel-head">
        <div>
          <p className="kicker">Link analysis</p>
          <h2>Neighborhood</h2>
        </div>
        <div className="controls">
          {[1, 2, 3].map((depth) => (
            <button key={depth} className={hops === depth ? "on" : ""} onClick={() => onHops(depth)} type="button">
              {depth} hop{depth === 1 ? "" : "s"}
            </button>
          ))}
          <button
            type="button"
            onClick={() => {
              if (!focusNode) return;
              if (pinned) onPin(focus, null);
              else onPin(focus, { fx: 420, fy: 280 });
            }}
          >
            {pinned ? "Unpin focus" : "Pin focus"}
          </button>
        </div>
      </header>
      <p className="focus-line">
        Focus <strong>{focusNode?.label || focus}</strong>
        <span>{data?.nodes?.length || 0} nodes</span>
        <span>{data?.links?.length || 0} edges</span>
      </p>
      <div className="canvas-wrap" ref={wrapRef}>
        <canvas ref={canvasRef} />
      </div>
      <ul className="legend">
        {Object.entries(summary).map(([kind, count]) => (
          <li key={kind}>
            <i style={{ background: kind === "Ip" ? COLORS.Ip : COLORS[kind] || "#6b7280" }} />
            {kind} {count}
          </li>
        ))}
      </ul>
      <p className="fine">Drag a node to pin it. Click a node to make it the hop origin. Gold nodes carry the crawler, scanner, and CitrixBleed 2 trio.</p>
    </section>
  );
}
