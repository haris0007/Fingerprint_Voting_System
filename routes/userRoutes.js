const express = require("express");
const bcrypt = require("bcrypt");
const UserModel = require("../models/userModel");
const UserRouter = express.Router();

async function hashFingerprint(fingerprint) {
    const saltRounds = 10;
    return await bcrypt.hash(fingerprint, saltRounds);
}

async function compareFingerprints(inputFingerprint, storedFingerprint) {
    return await bcrypt.compare(inputFingerprint, storedFingerprint);
}

// Normalize fingerprint before hashing
function normalizeFingerprint(fingerprint) {
    return fingerprint.trim().replace(/\s+/g, "").toLowerCase();
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

                return btoa(String.fromCharCode(...new Uint8Array(credential.rawId)))
                    .substring(0, 30); // Trim fingerprint to reduce variations
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
                body: JSON.stringify({ email, fingerprintId }),
            });

            const data = await res.json();
            alert(data.message);
        }

        async function checkUser() {
            const email = document.getElementById("emailLogin").value;
            const fingerprintId = await getFingerprint();
            if (!fingerprintId) return;

            const res = await fetch("/fingerprint-auth/checkuser", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, fingerprintId }),
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
                body: JSON.stringify({ fingerprintId }),
            });

            const data = await res.json();
            alert(data.message);
        }
    </script>
</body>
</html>`);
});

UserRouter.post("/register", async (req, res) => {
    const { email, fingerprintId } = req.body;

    if (!email || !fingerprintId) {
        return res.status(400).json({ message: "Email and fingerprint are required" });
    }

    try {
        const existingUser = await UserModel.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: "Email already registered" });
        }

        const normalizedFingerprint = normalizeFingerprint(fingerprintId);
        const hashedFingerprint = await hashFingerprint(normalizedFingerprint);

        const newUser = new UserModel({ email, fingerprint: hashedFingerprint });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
    }
});

UserRouter.post("/checkuser", async (req, res) => {
    const { email, fingerprintId } = req.body;

    if (!email || !fingerprintId) {
        return res.status(400).json({ message: "Email and fingerprint are required" });
    }

    try {
        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: "Authentication failed" });
        }

        const normalizedFingerprint = normalizeFingerprint(fingerprintId);
        const isMatch = await compareFingerprints(normalizedFingerprint, user.fingerprint);

        if (!isMatch) {
            return res.status(401).json({ message: "Authentication failed" });
        }

        res.json({ message: "Login successful" });
    } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
    }
});

UserRouter.post("/findwho", async (req, res) => {
    const { fingerprintId } = req.body;

    if (!fingerprintId) {
        return res.status(400).json({ message: "Fingerprint is required" });
    }

    try {
        const users = await UserModel.find();
        const normalizedFingerprint = normalizeFingerprint(fingerprintId);

        const matchPromises = users.map(async (user) => {
            const isMatch = await compareFingerprints(normalizedFingerprint, user.fingerprint);
            return isMatch ? user.email : null;
        });

        const results = await Promise.all(matchPromises);
        const matchedUser = results.find((email) => email !== null);

        if (!matchedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ message: `User found: ${matchedUser}` });
    } catch (error) {
        res.status(500).json({ message: "Internal server error", error });
    }
});

module.exports = UserRouter;
