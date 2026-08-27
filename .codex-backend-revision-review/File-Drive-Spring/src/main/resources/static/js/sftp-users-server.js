async function loadUsers() {
    const container = document.getElementById('users');
    const empty = document.getElementById('users-empty');
    const errBox = document.getElementById('users-error');

    try {
        const res = await fetch(DATA_URL, { headers: { 'Accept': 'application/json' } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const data = await res.json();
        const connected = Array.isArray(data?.users)
            ? data.users.filter(u => u && u.connected)
            : [];

        // Clear prior rendered items (but keep the empty/err elements)
        [...container.querySelectorAll('.user-row')].forEach(n => n.remove());

        if (!connected.length) {
            empty.style.display = 'block';
        } else {
            empty.style.display = 'none';

            const frag = document.createDocumentFragment();
            connected.forEach(u => {
                const row = document.createElement('div');
                row.className = 'user-row';
                row.style.display = 'grid';
                row.style.gridTemplateColumns = '1fr auto';
                row.style.gap = '.5rem';
                row.style.alignItems = 'center';
                row.style.padding = '.5rem .75rem';
                row.style.border = '1px solid rgba(255,255,255,.08)';
                row.style.borderRadius = '6px';
                row.style.background = '#0e1116';

                row.innerHTML = `
          <div style="display:flex; flex-direction:column">
            <strong style="letter-spacing:.2px">${u.username ?? ''}</strong>
            <span class="muted" style="font-size:.9rem; opacity:.9">
              since: ${u.time ?? '—'}
            </span>
          </div>
          <span style="font-weight:700; color:#34d399">● Online</span>
        `;
                frag.appendChild(row);
            });
            container.appendChild(frag);
        }

        errBox.style.display = 'none';
    } catch (err) {
        errBox.textContent = 'Error loading users: ' + err.message;
        errBox.style.display = 'block';
    }
}
