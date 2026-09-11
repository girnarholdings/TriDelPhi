const el = id => document.getElementById(id);
const preview = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
async function api(path, body) {
  const response = await fetch(path, body === undefined ? { credentials: "same-origin" } : {
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data;
  try { data = await response.json(); }
  catch { throw new Error("The portal could not complete this request. If you clicked Create, check github.com/codespaces before trying again."); }
  if (!response.ok) throw new Error(data.error || "Please try again later.");
  return data;
}
async function start() {
  if (preview) {
    el("status").textContent = "Design preview — cloud sign-in and workspace creation are available on scan.tridelphi.com. Local instructions work here.";
    const connect = el("signin").querySelector("a.button");
    connect.href = "https://scan.tridelphi.com/";
    connect.textContent = "Open live scan portal →";
    return;
  }
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
    el("status").classList.add("connected");
  } catch (error) { el("status").textContent = error.message === "Sign in with the TriDelPhi GitHub App to continue." ? "Ready when you are. Connect GitHub to use a cloud workspace." : error.message; }
}
for (const method of ["cloud", "local"]) {
  el(`choose-${method}`).addEventListener("click", () => {
    for (const option of ["cloud", "local"]) {
      const active = method === option;
      el(`${option}-panel`).hidden = !active;
      el(`choose-${option}`).setAttribute("aria-pressed", String(active));
      el(`choose-${option}`).classList.toggle("selected", active);
    }
  });
}
for (const button of document.querySelectorAll("[data-copy]")) {
  button.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(button.dataset.copy); el("copy-status").textContent = "Command copied. Replace your-project.zip with your filename."; }
    catch { el("copy-status").textContent = "Select the command and copy it with your keyboard."; }
  });
}
let creating = false;
el("billing").addEventListener("change", () => {
  el("codespaces").disabled = creating || !el("billing").checked;
});
el("codespaces").addEventListener("click", async () => {
  if (preview || creating || !el("billing").checked) return;
  creating = true;
  el("codespaces").disabled = true;
  el("launch").hidden = true;
  el("status").textContent = "Checking access and creating your 2-core workspace…";
  try {
    const result = await api("/api/codespaces", { acceptGitHubBilling: true, createWorkspace: true });
    const target = new URL(result.url);
    if (target.protocol !== "https:" || !/^[a-z0-9-]+\.github\.dev$/.test(target.hostname) || target.port || target.username || target.password || target.pathname !== "/" || target.search || target.hash) throw new Error("Workspace link could not be verified. Check github.com/codespaces before trying again.");
    el("status").textContent = result.message;
    el("launch").href = target.href;
    el("launch").hidden = false;
  } catch (error) { el("status").textContent = error.message; }
  finally { creating = false; el("codespaces").disabled = !el("billing").checked; }
});
el("logout").addEventListener("click", async () => {
  try { await api("/auth/logout", {}); location.reload(); }
  catch (error) { el("status").textContent = error.message; }
});
start();
