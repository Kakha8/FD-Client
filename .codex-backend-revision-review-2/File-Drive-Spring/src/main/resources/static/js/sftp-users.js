// /static/js/sftp-users.js
(() => {
    const ACTIVE_URL =
        typeof window.ACTIVE_URL === "string" && window.ACTIVE_URL.length
            ? window.ACTIVE_URL
            : "/sessions/active";

    const els = {
        list:  document.getElementById("users"),
        empty: document.getElementById("users-empty"),
        error: document.getElementById("users-error"),
        btn:   document.getElementById("users-refresh"),
        panel: document.getElementById("usersPanel"),
    };

    function setLoading(v){
        if (!els.list) return;
        if (v){
            els.list.setAttribute("aria-busy","true");
            els.list.dataset.prevHtml = els.list.innerHTML;
            els.list.innerHTML = '<div class="muted" style="opacity:.9">Loading users…</div>';
            if (els.error) els.error.style.display = "none";
            if (els.btn)   els.btn.disabled = true;
        } else {
            els.list.removeAttribute("aria-busy");
            if (els.btn) els.btn.disabled = false;
        }
    }

    const esc = s => String(s ?? "")
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");

    function timeAgo(iso){
        if (!iso) return "unknown";
        const d = new Date(iso), ms = Date.now() - d.getTime();
        if (!Number.isFinite(ms)) return "invalid date";
        const s = Math.floor(ms/1000), m = Math.floor(s/60), h = Math.floor(m/60), dA = Math.floor(h/24);
        const t = s < 45 ? `${s}s` : m < 60 ? `${m}m` : h < 24 ? `${h}h` : `${dA}d`;
        return `<span title="${d.toISOString()}">${t} ago</span>`;
    }

    const row = x => `
    <div role="listitem" style="border:1px solid rgba(255,255,255,.08); border-radius:6px; padding:.6rem .75rem;">
      <div style="display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap;">
        <div style="font-weight:600">${esc(x.username)}</div>
        <div class="muted" style="font-size:.9rem">Remote: <strong>${esc(x.remote)||"—"}</strong></div>
      </div>
      <div class="muted" style="margin-top:.35rem; display:flex; gap:1rem; flex-wrap:wrap; font-size:.92rem;">
        <div>Session: <code>${esc(x.sessionId)}</code></div>
        <div>Created: <span title="${esc(x.createdAt)}">${esc(x.createdAt)}</span></div>
        <div>Last seen: ${timeAgo(x.lastSeen)}</div>
      </div>
    </div>`;

    function render(list){
        if (!els.list || !els.empty) return;
        if (!list || list.length === 0){
            els.list.innerHTML = "";
            els.empty.style.display = "";
            return;
        }
        els.empty.style.display = "none";
        els.list.setAttribute("role","list");
        els.list.innerHTML = list.map(row).join("");
    }

    function showError(msg){
        if (els.error){
            els.error.textContent = msg;
            els.error.style.display = "";
        }
    }

    async function loadUsers(){
        try{
            setLoading(true);
            const res = await fetch(`${ACTIVE_URL}?_=${Date.now()}`, {
                headers: { "Accept":"application/json" },
                credentials: "same-origin",
            });
            const ct = res.headers.get("content-type") || "";
            if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
            if (!ct.includes("application/json")) throw new Error("Endpoint returned non-JSON");
            const data = await res.json();
            if (!data || !Array.isArray(data.sessions)) throw new Error("Unexpected JSON shape");
            render(data.sessions);
            if (els.error) els.error.style.display = "none";
        } catch (e){
            console.error("[sftp-users]", e);
            showError(e.message || "Failed to load users.");
            if (els.list && els.list.dataset.prevHtml) els.list.innerHTML = els.list.dataset.prevHtml;
        } finally {
            setLoading(false);
        }
    }

    window.loadUsers = loadUsers;

    // Refresh button
    if (els.btn) els.btn.addEventListener("click", loadUsers);

    if (els.panel && !els.panel.classList.contains("hidden")) loadUsers();

    console.log("[sftp-users] ready; ACTIVE_URL =", ACTIVE_URL);
})();
