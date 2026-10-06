import { useEffect, useRef } from "react";
import maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";

export default function Heatmap({ heat, layer, onLayer }) {
  const mapNode = useRef(null);
  const mapRef = useRef(null);

  useEffect(() => {
    if (!mapNode.current || mapRef.current) return undefined;
    const map = new maplibregl.Map({
      container: mapNode.current,
      style: {
        version: 8,
        sources: {},
        layers: [{ id: "background", type: "background", paint: { "background-color": "#e7e1d6" } }],
      },
      center: [10, 20],
      zoom: 1.1,
      attributionControl: false,
    });
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
    mapRef.current = map;
    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !heat) return undefined;
    let cancelled = false;
    const rows = heat[layer] || [];
    const counts = new Map(rows.map((row) => [row.map_name, row.count]));
    const max = Math.max(1, ...rows.map((row) => row.count));

    function paint() {
      fetch("/countries.geojson")
        .then((response) => response.json())
        .then((geo) => {
          if (cancelled) return;
          const data = {
            ...geo,
            features: geo.features.map((feature) => ({
              ...feature,
              properties: {
                ...feature.properties,
                count: counts.get(feature.properties.name) || 0,
              },
            })),
          };
          if (map.getLayer("countries")) map.removeLayer("countries");
          if (map.getLayer("borders")) map.removeLayer("borders");
          if (map.getSource("countries")) map.removeSource("countries");
          map.addSource("countries", { type: "geojson", data });
          map.addLayer({
            id: "countries",
            type: "fill",
            source: "countries",
            paint: {
              "fill-color": [
                "interpolate",
                ["linear"],
                ["get", "count"],
                0,
                "#efeae2",
                Math.max(1, max * 0.15),
                "#e7c7a2",
                Math.max(2, max * 0.4),
                "#d4844a",
                max,
                "#8f2d2d",
              ],
              "fill-opacity": 0.95,
            },
          });
          map.addLayer({
            id: "borders",
            type: "line",
            source: "countries",
            paint: { "line-color": "#c9c0b2", "line-width": 0.6 },
          });
        });
    }

    if (map.isStyleLoaded()) paint();
    else map.once("load", paint);
    return () => {
      cancelled = true;
    };
  }, [heat, layer]);

  const rows = heat?.[layer] || [];
  const mapped = new Set(rows.map((row) => row.map_name));

  return (
    <section className="panel">
      <header className="panel-head">
        <div>
          <p className="kicker">Attack surface</p>
          <h2>{layer === "source" ? "Source infrastructure" : "Sensor pressure"}</h2>
        </div>
        <div className="controls">
          <button type="button" className={layer === "source" ? "on" : ""} onClick={() => onLayer("source")}>
            Sources
          </button>
          <button type="button" className={layer === "destination" ? "on" : ""} onClick={() => onLayer("destination")}>
            Sensor pressure
          </button>
        </div>
      </header>
      <p className="focus-line">
        {layer === "source"
          ? "Where the malicious addresses geolocate."
          : heat?.note}
      </p>
      <div className="map" ref={mapNode} />
      <ol className="rank">
        {rows.slice(0, 8).map((row) => (
          <li key={`${row.map_name}-${row.code}`}>
            <span>{row.name}</span>
            <strong>{row.count}</strong>
          </li>
        ))}
      </ol>
      <p className="fine">
        {heat?.citation} Countries without a polygon in this atlas, including any name not in the basemap, stay in the list only.
        {mapped.size === 0 ? " Import GreyNoise data to fill the map." : ""}
      </p>
    </section>
  );
}
