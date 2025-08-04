// Firebase config
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getDatabase, ref, onValue } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-database.js";

const firebaseConfig = {
  apiKey: "AIzaSyByM5CbPjCo6WSeb4RU2_RA_IPQEmKdLBA",
  authDomain: "honeypot-715b9.firebaseapp.com",
  projectId: "honeypot-715b9",
  storageBucket: "honeypot-715b9.firebasestorage.app",
  messagingSenderId: "556848903405",
  appId: "1:556848903405:web:b338b330f3c02d042cc8e4",
  databaseURL: "https://honeypot-715b9-default-rtdb.firebaseio.com/"
};

const app = initializeApp(firebaseConfig);
const db = getDatabase(app);

const logRef = ref(db, 'honeypot_logs');
const tableBody = document.getElementById('log-table-body');

// Listen to realtime data
onValue(logRef, (snapshot) => {
  tableBody.innerHTML = ''; // clear table
  const logs = snapshot.val();

  if (logs) {
    Object.values(logs).reverse().forEach(log => {
      const row = document.createElement('tr');

      row.innerHTML = `
        <td>${log.ip}</td>
        <td>${log.port}</td>
        <td>${log.data}</td>
        <td>${log.time}</td>

      `;

      tableBody.appendChild(row);
    });
  }
});
