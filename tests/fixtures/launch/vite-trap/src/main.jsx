import { createRoot } from "react-dom/client";
import App from "./App.jsx";

const script = document.createElement("script");
script.src = "https://static.hotjar.com/c/hotjar-9.js";
document.body.appendChild(script);

createRoot(document.getElementById("root")).render(<App />);
