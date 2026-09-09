const el = id => document.getElementById(id);
async function api(path, body) {
  const response = await fetch(path, body === undefined ? { credentials: "same-origin" } : {
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Please try again later.");
  return data;
}
async function start() {
  try {
    const config = await api("/api/config");
    const target = new URL(config.installUrl);
    if (target.origin === "https://github.com" && target.pathname.startsWith("/apps/")) {
      el("install").href = target.href;
      el("install").hidden = false;
    }
    const session = await api("/api/session");
    el("status").textContent = `Signed in as ${session.login} · ${session.tier} account`;
    el("signin").hidden = true;
    el("billing").disabled = false;
    el("logout").hidden = false;
  } catch (error) { el("status").textContent = error.message; }
}
el("billing").addEventListener("change", () => {
  el("codespaces").disabled = !el("billing").checked;
  el("launch").hidden = true;
});
el("codespaces").addEventListener("click", async () => {
  el("codespaces").disabled = true;
  el("launch").hidden = true;
  el("status").textContent = "Checking GitHub access and billing…";
  try {
    const result = await api("/api/codespaces", { acceptGitHubBilling: el("billing").checked });
    const target = new URL(result.url);
    if (target.origin !== "https://github.com" || target.pathname !== "/codespaces/new") throw new Error("GitHub link could not be verified.");
    el("status").textContent = result.message;
    el("launch").href = target.href;
    el("launch").hidden = false;
  } catch (error) { el("status").textContent = error.message; }
  finally { el("codespaces").disabled = !el("billing").checked; }
});
el("logout").addEventListener("click", async () => {
  try { await api("/auth/logout", {}); location.reload(); }
  catch (error) { el("status").textContent = error.message; }
});
start();
