import { useCallback, useEffect, useState } from "react";
import Graph from "./Graph";
import Heatmap from "./Heatmap";

const FOCUS = "cve:CVE-2026-88771";

async function getJson(url) {
  const response = await fetch(url);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || response.statusText);
  return body;
}

export default function App() {
  const [brief, setBrief] = useState(null);
  const [graph, setGraph] = useState(null);
  const [heat, setHeat] = useState(null);
  const [focus, setFocus] = useState(FOCUS);
  const [hops, setHops] = useState(2);
  const [pins, setPins] = useState({});
  const [layer, setLayer] = useState("destination");
  const [source, setSource] = useState("greynoise");
  const [mode, setMode] = useState("file");
  const [query, setQuery] = useState("cve:CVE-2026-88771 last_seen:30d AND spoofable:false AND classification:malicious");
  const [precursor, setPrecursor] = useState(false);
  const [addedAfter, setAddedAfter] = useState("");
  const [status, setStatus] = useState("Load the GreyNoise export to score this storm.");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async (nextFocus = focus, nextHops = hops) => {
    const [nextBrief, nextGraph, nextHeat] = await Promise.all([
      getJson("/forecast?cve=CVE-2026-88771"),
      getJson(`/graph?focus=${encodeURIComponent(nextFocus)}&hops=${nextHops}`),
      getJson("/heatmap"),
    ]);
    setBrief(nextBrief);
    setGraph(nextGraph);
    setHeat(nextHeat);
  }, [focus, hops]);

  useEffect(() => {
    refresh()
      .then(() => setStatus("Forecast is scored from the imported GreyNoise snapshot."))
      .catch(() => setStatus("ArcadeDB is up. Import the GreyNoise file to fill the forecast."));
  }, [refresh]);

  async function changeFocus(next) {
    setFocus(next);
    setError("");
    try {
      setGraph(await getJson(`/graph?focus=${encodeURIComponent(next)}&hops=${hops}`));
    } catch (err) {
      setError(err.message);
    }
  }

  async function changeHops(next) {
    setHops(next);
    try {
      setGraph(await getJson(`/graph?focus=${encodeURIComponent(focus)}&hops=${next}`));
    } catch (err) {
      setError(err.message);
    }
  }

  function pin(id, value) {
    setPins((current) => {
      const next = { ...current };
      if (value) next[id] = value;
      else delete next[id];
      return next;
    });
  }

  async function onImport(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setStatus("Importing into ArcadeDB…");
    try {
      const response = await fetch("/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source,
          mode: source === "taxii" ? "file" : mode,
          query: mode === "api" ? query : null,
          precursor,
          added_after: addedAfter || null,
        }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Import failed");
      setStatus(`Imported ${body.vertices} vertices and ${body.edges} edges from ${source}.`);
      await refresh(FOCUS, hops);
      setFocus(FOCUS);
    } catch (err) {
      setError(err.message);
      setStatus("Import did not finish.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <header className="top">
        <div>
          <p className="kicker">GreyNoise precursors to KEV</p>
          <h1>Cyber Weather</h1>
        </div>
        <form className="import" onSubmit={onImport}>
          <label>
            Source
            <select
              value={source === "taxii" ? "taxii" : mode}
              onChange={(event) => {
                const value = event.target.value;
                if (value === "taxii") setSource("taxii");
                else {
                  setSource("greynoise");
                  setMode(value);
                }
              }}
            >
              <option value="file">GreyNoise file</option>
              <option value="api">GreyNoise API</option>
              <option value="taxii">TAXII 2.1 :4200</option>
            </select>
          </label>
          {source === "greynoise" && mode === "api" && (
            <label className="grow">
              GNQL
              <input value={query} onChange={(event) => setQuery(event.target.value)} />
            </label>
          )}
          {source === "taxii" && (
            <label>
              added_after
              <input value={addedAfter} onChange={(event) => setAddedAfter(event.target.value)} placeholder="optional" />
            </label>
          )}
          {source === "greynoise" && (
            <label className="check">
              <input type="checkbox" checked={precursor} onChange={(event) => setPrecursor(event.target.checked)} />
              Precursor query
            </label>
          )}
          <button type="submit" disabled={busy}>{busy ? "Importing" : "Import"}</button>
        </form>
      </header>
      <p className={error ? "status bad" : "status"}>{error || status}</p>
      <Forecast brief={brief} />
      <div className="grid">
        <Graph data={graph} hops={hops} onHops={changeHops} focus={focus} onFocus={changeFocus} pins={pins} onPin={pin} />
        <Heatmap heat={heat} layer={layer} onLayer={setLayer} />
      </div>
    </main>
  );
}

function Forecast({ brief }) {
  if (!brief) {
    return (
      <section className="brief empty">
        <h2>Forecast</h2>
        <p>No scored CVE yet.</p>
      </section>
    );
  }
  return (
    <section className="brief">
      <div className="brief-top">
        <div>
          <p className="kicker">{brief.cve}</p>
          <h2>{brief.condition}</h2>
          <p className="nature">{brief.nature}</p>
          {brief.after_landfall_note && <p className="landfall">{brief.after_landfall_note}</p>}
        </div>
        <div className="confidence">
          <span>Confidence</span>
          <strong>{Math.round(brief.confidence * 100)}%</strong>
        </div>
      </div>
      <dl className="metrics">
        <div><dt>Crawler</dt><dd>{brief.precursors.crawler}</dd></div>
        <div><dt>Scanner</dt><dd>{brief.precursors.scanner}</dd></div>
        <div><dt>CitrixBleed 2</dt><dd>{brief.precursors.citrixbleed2}</dd></div>
        <div><dt>Trio</dt><dd>{brief.precursors.trio}</dd></div>
        <div><dt>Reused before 24 Sep</dt><dd>{brief.first_seen.reused_before_sep24}</dd></div>
        <div><dt>After disclosure</dt><dd>{brief.first_seen.on_or_after_disclosure}</dd></div>
        <div><dt>Sessions</dt><dd>{brief.sessions.sum.toLocaleString()}</dd></div>
        <div><dt>Median / max</dt><dd>{brief.sessions.median} / {brief.sessions.max.toLocaleString()}</dd></div>
      </dl>
      <ol className="timeline">
        {brief.timeline.map((event) => (
          <li key={`${event.at}-${event.title}`}>
            <time>{event.at.replace("T", " ").replace("Z", " UTC")}</time>
            <span>{event.title}</span>
          </li>
        ))}
      </ol>
      <div className="split">
        <div>
          <h3>What to do</h3>
          <ul>{brief.actions.map((action) => <li key={action}>{action}</li>)}</ul>
        </div>
        <div>
          <h3>KEV</h3>
          <p>{brief.kev.listed ? `${brief.kev.source} · added ${brief.kev.date_added || "date unknown"}` : "Not listed"}</p>
          <p className="fine">{brief.exposure_citation}</p>
          <h3>Limits</h3>
          <ul className="limits">{brief.limits.map((limit) => <li key={limit}>{limit}</li>)}</ul>
        </div>
      </div>
    </section>
  );
}
