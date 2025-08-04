// firebase.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/9.6.1/firebase-app.js";
import { getDatabase, ref, push } from "https://www.gstatic.com/firebasejs/9.6.1/firebase-database.js";

const firebaseConfig = {
  apiKey: "AIzaSyByM5CbPjCo6WSeb4RU2_RA_IPQEmKdLBA",
  authDomain: "honeypot-715b9.firebaseapp.com",
  projectId: "honeypot-715b9",
  storageBucket: "honeypot-715b9.appspot.com",
  messagingSenderId: "556848903405",
  appId: "1:556848903405:web:b338b330f3c02d042cc8e4",
  databaseURL: "https://honeypot-715b9-default-rtdb.firebaseio.com/"
};

const app = initializeApp(firebaseConfig);
export const db = getDatabase(app);
export const logRef = ref(db, "clone_access");
export const pushLog = (data) => push(logRef, data);

