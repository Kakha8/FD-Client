"use strict";

import { getQueryPath, load, formatBytes } from "./file-browser.js";

const $ = (sel) => document.querySelector(sel);

/* ---------- Elements ---------- */
const fileInput = $('#file-input');
const btnUpload = $('#btn-upload');
const uploads = $('#uploads');

/* ---------- Event wiring ---------- */
if (btnUpload && fileInput) {
    btnUpload.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', () => {
        if (!fileInput.files?.length) return;
        const currentPath = getQueryPath();
        for (const file of fileInput.files) startUpload(file, currentPath);
        // allow selecting the same file again later
        fileInput.value = '';
    });
}

/* ---------- Upload flow ---------- */
function startUpload(file, currentPath) {
    // Build row
    const row = document.createElement('div');
    row.className = 'upload-row';
    row.innerHTML = `
    <div class="upload-head">
      <div class="upload-name" title="${file.name}">${file.name}</div>
      <div class="upload-size">${formatBytes(file.size)}</div>
    </div>
    <div class="upload-bar"><div class="bar"></div></div>
    <div class="upload-status" aria-live="polite">Waiting…</div>
    <div class="upload-actions">
      <button type="button" class="btn small danger cancelBtn" disabled>Cancel</button>
    </div>
  `;
    uploads?.prepend(row);

    const bar = row.querySelector('.bar');
    const status = row.querySelector('.upload-status');
    const cancelBtn = row.querySelector('.cancelBtn');

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');

    // Spring Security CSRF support
    const token = document.querySelector('meta[name="_csrf"]')?.content;
    const header = document.querySelector('meta[name="_csrf_header"]')?.content;
    if (token && header) xhr.setRequestHeader(header, token);

    const fd = new FormData();
    fd.append('file', file);
    fd.append('selectedPath', currentPath || '');

    cancelBtn.disabled = false;
    cancelBtn.onclick = () => xhr.abort();

    xhr.upload.onprogress = (evt) => {
        if (!bar || !status) return;
        if (evt.lengthComputable) {
            const pct = Math.round((evt.loaded / evt.total) * 100);
            bar.style.width = pct + '%';
            status.textContent = pct + '%';
        } else {
            status.textContent = 'Uploading…';
        }
    };

    xhr.onload = () => {
        if (cancelBtn) cancelBtn.disabled = true;
        if (bar) bar.style.width = '100%';

        if (!status) return;

        if (xhr.status >= 200 && xhr.status < 300) {
            try {
                const data = JSON.parse(xhr.responseText);
                if (data.ok) {
                    status.textContent = `Done — ${data.fileName} (${formatBytes(data.bytes)})`;
                    status.classList.add('ok');
                    // Refresh list so the new file appears
                    load(getQueryPath());
                } else {
                    status.textContent = data.message || 'Upload failed';
                    status.classList.add('err');
                }
            } catch {
                status.textContent = 'Done (response parse error)';
                status.classList.add('ok');
                load(getQueryPath());
            }
        } else {
            status.textContent = `Failed (${xhr.status})`;
            status.classList.add('err');
        }
    };

    xhr.onerror = () => {
        if (!status || !cancelBtn) return;
        cancelBtn.disabled = true;
        status.textContent = 'Network error';
        status.classList.add('err');
    };

    xhr.onabort = () => {
        if (!status || !cancelBtn) return;
        cancelBtn.disabled = true;
        status.textContent = 'Canceled';
    };

    xhr.send(fd);
}
