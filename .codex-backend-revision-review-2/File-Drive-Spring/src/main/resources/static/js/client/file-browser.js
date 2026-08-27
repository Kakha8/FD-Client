"use strict";

/* ---------- Utilities ---------- */
const $ = (sel) => document.querySelector(sel);

export function joinPath(a, b) {
    if (!a) return b || "";
    if (!b) return a;
    return (a.replace(/\/+$/,'') + '/' + b.replace(/^\/+/, '')).replace(/\/+/g,'/');
}
export function parentPath(p) {
    if (!p) return "";
    const parts = p.split('/').filter(Boolean);
    parts.pop();
    return parts.join('/');
}
function setQuery(path) {
    const url = new URL(window.location);
    if (path) url.searchParams.set('selectedDir', path);
    else url.searchParams.delete('selectedDir');
    history.pushState({ path }, '', url);
}
export function getQueryPath() {
    return new URL(location.href).searchParams.get('selectedDir') || '';
}
export function formatBytes(n) {
    if (n == null) return '';
    const u = ['B','KB','MB','GB','TB'];
    let i = 0, x = Number(n);
    while (x >= 1024 && i < u.length-1) { x /= 1024; i++; }
    return x.toFixed(x >= 10 || i===0 ? 0 : 1) + ' ' + u[i];
}
function extFromName(name){
    const m = (name || '').match(/\.([^.]+)$/);
    return m ? m[1].toLowerCase() : '';
}

/* ---------- Selection state ---------- */
const selectedPaths = new Set();
export function getSelectedPaths() { return Array.from(selectedPaths); }

function updateSelectionUI() {
    const tbody = $('#tbody');
    if (!tbody) return;
    tbody.querySelectorAll('tr.file-row').forEach(tr => {
        tr.classList.toggle('selected', selectedPaths.has(tr.dataset.path));
        tr.setAttribute('aria-selected', selectedPaths.has(tr.dataset.path) ? 'true' : 'false');
    });
}
function clearSelection() {
    selectedPaths.clear();
    updateSelectionUI();
}
function selectOnly(path) {
    selectedPaths.clear();
    selectedPaths.add(path);
    updateSelectionUI();
}
function toggleSelect(path) {
    if (selectedPaths.has(path)) selectedPaths.delete(path);
    else selectedPaths.add(path);
    updateSelectionUI();
}

/* ---------- UI: breadcrumbs ---------- */
function renderBreadcrumb(path) {
    const container = $('#path');
    const parts = path ? path.split('/').filter(Boolean) : [];
    let acc = '';
    const segs = [`<span class="crumb"><a href="#" data-path="">/</a></span>`];
    parts.forEach((p) => {
        acc = joinPath(acc, p);
        segs.push(`<span class="crumb-sep">/</span><span class="crumb"><a href="#" data-path="${acc}">${p}</a></span>`);
    });
    container.innerHTML = segs.join('');

    container.querySelectorAll('a[data-path]').forEach(a => {
        a.addEventListener('click', (e) => {
            e.preventDefault();
            load(a.dataset.path);
        });
    });

    const upBtn = $('#btn-up');
    if (upBtn) {
        upBtn.onclick = () => {
            const up = parentPath(path);
            if (up !== path) load(up);
        };
    }
}

/* ---------- Data ---------- */
async function fetchDir(path) {
    const err = $('#error');
    const spinner = $('#loading');
    if (err) {
        err.style.display = 'none';
        err.textContent = '';
    }
    if (spinner) spinner.style.display = 'inline';
    try {
        const res = await fetch(`/api/dirs?selectedDir=${encodeURIComponent(path)}`, { cache:'no-store' });
        const data = await res.json();
        if (!Array.isArray(data)) {
            throw new Error(data && data.error ? data.error : 'Unexpected response');
        }
        return data;
    } finally {
        if (spinner) spinner.style.display = 'none';
    }
}

/* ---------- Table ---------- */
function renderTable(currentPath, items) {
    const tbody = $('#tbody');
    if (!tbody) return;

    // Clear selection on new directory load
    selectedPaths.clear();

    if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="muted" style="padding:1.2rem 1rem; text-align:center; opacity:.8;">Empty</td></tr>`;
        return;
    }
    items.sort((a,b) => {
        if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
        return a.name.localeCompare(b.name, undefined, { sensitivity:'base' });
    });

    const rows = [];
    for (const it of items) {
        const isFolder = it.type === 'folder';
        const when = it.lastModified ? new Date(it.lastModified).toLocaleString() : '';
        const size = isFolder ? '—' : formatBytes(it.size);
        const typeLabel = isFolder ? 'Directory' : (extFromName(it.name) || 'File');
        const iconFolder = `<svg class="ico" viewBox="0 0 24 24" fill="none"><path d="M3 7a2 2 0 012-2h4l2 2h6a2 2 0 012 2v7a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" fill="currentColor"/></svg>`;
        const iconFile = `<svg class="ico" viewBox="0 0 24 24" fill="none"><path d="M6 2h7l5 5v13a2 2 0 01-2 2H6a2 2 0 01-2-2V4a2 2 0 012-2z" stroke="currentColor" stroke-width="1.3" fill="none"/><path d="M13 2v5h5" stroke="currentColor" stroke-width="1.3" fill="none"/></svg>`;

        const itemPath = it.path || joinPath(currentPath, it.name);

        const nameCell = isFolder
            ? `<div class="name-cell">
            ${iconFolder}
            <button class="btn secondary btn-open" data-path="${itemPath}" style="padding:.2rem .5rem;">${it.name}</button>
            <span class="badge">folder</span>
         </div>`
            : `<div class="name-cell">
            ${iconFile}<span>${it.name}</span>
         </div>`;

        rows.push(`
      <tr class="file-row" tabindex="0" role="row" data-path="${itemPath}" data-type="${isFolder ? 'folder' : 'file'}" data-name="${it.name}">
        <td>${nameCell}</td>
        <td class="hide-sm muted">${typeLabel}</td>
        <td class="hide-sm muted">${size}</td>
        <td class="muted">${when}</td>
      </tr>
    `);
    }
    tbody.innerHTML = rows.join('');

    // open folder buttons
    tbody.querySelectorAll('.btn-open[data-path]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            load(btn.dataset.path);
        });
    });

    // Row selection
    tbody.addEventListener('click', (e) => {
        const tr = e.target.closest('tr.file-row');
        if (!tr) return;

        // Ignore clicks on explicit open buttons
        if (e.target.closest('.btn-open')) return;

        const path = tr.dataset.path;
        const multi = e.ctrlKey || e.metaKey;

        if (multi) {
            toggleSelect(path);
        } else {
            selectOnly(path);
        }
    });

    tbody.addEventListener('dblclick', (e) => {
        const tr = e.target.closest('tr.file-row');
        if (!tr) return;
        if (tr.dataset.type === 'folder') {
            load(tr.dataset.path);
        }
    });

    updateSelectionUI();
}

/* ---------- Controller ---------- */
export async function load(path) {
    try {
        setQuery(path);
        renderBreadcrumb(path);
        const data = await fetchDir(path);
        renderTable(path, data);
    } catch (e) {
        const err = $('#error');
        if (err) {
            err.textContent = e && e.message ? e.message : 'Failed to load';
            err.style.display = 'inline-block';
        }
        const tbody = $('#tbody');
        if (tbody) tbody.innerHTML = '';
    }
}

/* ---------- Wiring ---------- */
function wireChrome() {
    const refresh = $('#btn-refresh');
    if (refresh) refresh.onclick = () => load(getQueryPath());

    window.addEventListener('popstate', () => load(getQueryPath()));
    // Initial load
    load(getQueryPath());
}

document.addEventListener('DOMContentLoaded', wireChrome);
