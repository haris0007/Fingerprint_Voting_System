const express = require("express");
const crypto = require("crypto");
const UserModel = require("../models/userModel");

const UserRouter = express.Router();

let leven; // Declare leven globally
import("leven").then((module) => {
    leven = module.default;
}).catch(console.error);

function hashFingerprint(fingerprint) {
    return crypto.createHash("sha256").update(fingerprint).digest("hex");
}

// Function to compute similarity between fingerprints
function isSimilarFingerprint(inputFingerprint, storedFingerprint) {
    if (!leven) return false; // Ensure leven is loaded
    const distance = leven(inputFingerprint, storedFingerprint);
    const similarity = ((Math.max(inputFingerprint.length, storedFingerprint.length) - distance) / Math.max(inputFingerprint.length, storedFingerprint.length)) * 100;
    return similarity > 85; // 85% threshold
}

UserRouter.get("/home", (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fingerprint Authentication</title>
</head>
<body>
    <h2>Register</h2>
    <input type="email" id="email" placeholder="Enter Email">
    <button onclick="register()">Register with Fingerprint</button>

    <h2>Login</h2>
    <input type="email" id="emailLogin" placeholder="Enter Email">
    <button onclick="checkUser()">Login with Fingerprint</button>

    <h2>Find Who</h2>
    <button onclick="findWho()">Find Who</button>

    <script>
        async function getFingerprint() {
            if (!window.PublicKeyCredential) {
                alert("WebAuthn not supported on this device!");
                return null;
            }

            try {
                const credential = await navigator.credentials.create({
                    publicKey: {
                        challenge: new Uint8Array(32),
                        rp: { name: "My App" },
                        user: { id: new Uint8Array(16), name: "user", displayName: "User" },
                        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                        authenticatorSelection: { authenticatorAttachment: "platform" },
                    }
                });

                return btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
            } catch (err) {
                alert("Fingerprint authentication failed!");
                return null;
            }
        }

        async function register() {
            const email = document.getElementById("email").value;
            const fingerprintId = await getFingerprint();
            if (!fingerprintId) return;

            const res = await fetch("/fingerprint-auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, fingerprint: fingerprintId }),
            });

            const data = await res.json();
            alert(data.message);
        }

        async function checkUser() {
            const email = document.getElementById("emailLogin").value;
            const fingerprintId = await getFingerprint();
            if (!fingerprintId) return;

            const res = await fetch("/fingerprint-auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, fingerprint: fingerprintId }),
            });

            const data = await res.json();
            alert(data.message);
        }

        async function findWho() {
            const fingerprintId = await getFingerprint();
            if (!fingerprintId) return;

            const res = await fetch("/fingerprint-auth/findwho", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ fingerprint: fingerprintId }),
            });

            const data = await res.json();
            alert(data.message);
        }
    </script>
</body>
</html>
`); // Serve HTML file
});

// Register Route
UserRouter.post("/register", async (req, res) => {
    const { email, fingerprint } = req.body;
    if (!email || !fingerprint) return res.status(400).json({ message: "Email and fingerprint are required" });

    try {
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "Email already registered" });

        const hashedFingerprint = hashFingerprint(fingerprint);
        const newUser = new UserModel({ email, fingerprint: hashedFingerprint });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});

// Login Route
UserRouter.post("/login", async (req, res) => {
    const { email, fingerprint } = req.body;
    if (!email || !fingerprint) return res.status(400).json({ message: "Email and fingerprint are required" });

    try {
        const user = await UserModel.findOne({ email });
        if (!user) return res.status(401).json({ message: "Authentication failed" });

        const hashedInput = hashFingerprint(fingerprint);
        const isMatch = isSimilarFingerprint(hashedInput, user.fingerprint);

        if (!isMatch) return res.status(401).json({ message: "Authentication failed" });

        res.json({ message: "Login successful" });
    } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
    }
});

// Find Who Route
UserRouter.post("/findwho", async (req, res) => {
    try {
        const { fingerprint } = req.body;
        if (!fingerprint) return res.status(400).json({ success: false, message: "Fingerprint data is required." });

        const users = await UserModel.find();
        let bestMatch = null;
        let bestScore = 0;

        users.forEach(user => {
            const similarityScore = ((Math.max(fingerprint.length, user.fingerprint.length) - leven(fingerprint, user.fingerprint)) / Math.max(fingerprint.length, user.fingerprint.length)) * 100;

            if (similarityScore > bestScore) {
                bestScore = similarityScore;
                bestMatch = user;
            }
        });

        if (bestScore >= 85) {
            return res.json({ success: true, message: `User found: ${bestMatch.email}` });
        } else {
            return res.json({ success: false, message: "No matching user found." });
        }
    } catch (error) {
        console.error("Error in /findwho:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

module.exports = UserRouter;



