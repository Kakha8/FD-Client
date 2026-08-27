(async function () {
    const tbody = document.getElementById("usersTbody");

    console.log("User role is:", userRole);

    if (userRole !== "admin") {
        window.location.href = "/login";
    }
    else{


        try {
            const res = await fetch("/api/user-info/all-user", {
                headers: {Accept: "application/json"},
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json(); // ex: { "user1": false, "admin": true }
            tbody.innerHTML = "";

            const entries = Object.entries(data);
            if (entries.length === 0) {
                tbody.innerHTML = `<tr><td colspan="2">No users found.</td></tr>`;
                return;
            }

            for (const [username, connected] of entries) {
                const tr = document.createElement("tr");

                const tdUser = document.createElement("td");
                tdUser.textContent = username;

                const tdStatus = document.createElement("td");
                tdStatus.textContent = connected ? "Online" : "Offline";

                tr.append(tdUser, tdStatus);
                tbody.appendChild(tr);
            }
        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="2">Failed to load: ${err.message}</td></tr>`;
        }
    }


})();
