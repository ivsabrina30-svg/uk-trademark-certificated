// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyDXnqA6YHHgfAKjZKYbLu9UyuCQ_AMkfp0",
    authDomain: "uk-trademark-certificated.firebaseapp.com",
    projectId: "uk-trademark-certificated",
    storageBucket: "uk-trademark-certificated.firebasestorage.app",
    messagingSenderId: "433651507943",
    appId: "1:433651507943:web:cefd95bb598bc3e28ff842",
    measurementId: "G-756SEFWRKW"
};

// Initialize Firebase Compat & Realtime Database Instance for index.html
if (typeof firebase !== 'undefined') {
    firebase.initializeApp(firebaseConfig);
    window.firebaseDatabaseInstance = firebase.database();
}