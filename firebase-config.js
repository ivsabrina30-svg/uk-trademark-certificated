// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyDXnqA6YHHgfAKjZKYbLu9UyuCQ_AMkfp0",
  authDomain: "uk-trademark-certificated.firebaseapp.com",
  databaseURL: "https://uk-trademark-certificated-default-rtdb.firebaseio.com",
  projectId: "uk-trademark-certificated",
  storageBucket: "uk-trademark-certificated.firebasestorage.app",
  messagingSenderId: "433651507943",
  appId: "1:433651507943:web:cefd95bb598bc3e28ff842",
  measurementId: "G-756SEFWRKW"
};

// Initialize Firebase Compat, Auth & Realtime Database Instance for index.html
if (typeof firebase !== 'undefined') {
  if (!firebase.apps || firebase.apps.length === 0) {
    firebase.initializeApp(firebaseConfig);
  }
  if (typeof firebase.database === 'function') {
    window.firebaseDatabaseInstance = firebase.database();
  }
  if (typeof firebase.auth === 'function') {
    window.firebaseAuthInstance = firebase.auth();
  }
}