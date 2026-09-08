import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AtlasApp } from "./AtlasApp";
import "./style.css";
const mode = new URLSearchParams(location.search).get("mode");
const atlas = mode === "atlas" || (import.meta.env.DEV && mode !== "workbench");
createRoot(document.getElementById("root")!).render(
  atlas ? <AtlasApp /> : <App />,
);
