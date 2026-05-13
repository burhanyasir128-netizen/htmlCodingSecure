const CryptoJS = require("crypto-js");

// CryptoJS Custom JSON Formatter (Frontend se match karne ke liye)
const CryptoJSAesJson = {
    stringify: function (cipherParams) {
        var j = {ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64)};
        if (cipherParams.iv) j.iv = cipherParams.iv.toString();
        if (cipherParams.salt) j.s = cipherParams.salt.toString();
        return JSON.stringify(j);
    },
    parse: function (jsonStr) {
        var j = JSON.parse(jsonStr);
        var cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: CryptoJS.enc.Base64.parse(j.ct)});
        if (j.iv) cipherParams.iv = CryptoJS.enc.Hex.parse(j.iv)
        if (j.s) cipherParams.salt = CryptoJS.enc.Hex.parse(j.s)
        return cipherParams;
    }
};

export default function handler(req, res) {
    // 1. CORS Headers - Allow Frontend to communicate
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

    // 2. Preflight Request (Fixes the "Failed to fetch" error)
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // 3. Only accept POST requests
    if (req.method !== 'POST') {
        return res.status(405).json({ status: "error", message: "Method Not Allowed" });
    }

    // ==========================================
    // APKI SECURE MASTER KEY (Jo Vercel par chupi rahegi)
    // ==========================================
    const REAL_MASTER_KEY = "Yasir123";

    try {
        const { encrypted_auth_vault, encrypted_master_vault, user_key } = req.body;

        if (!encrypted_auth_vault || !encrypted_master_vault || !user_key) {
            return res.status(400).json({ status: "error", message: "Missing payload parameters" });
        }

        let decryptedCode = null;

        // Step 1: Try decrypting with User's Access Key
        try {
            const bytes = CryptoJS.AES.decrypt(encrypted_auth_vault, user_key, { format: CryptoJSAesJson });
            const result = bytes.toString(CryptoJS.enc.Utf8);
            if (result) decryptedCode = JSON.parse(result);
        } catch (e) {
            decryptedCode = null;
        }

        // Step 2: If User Key fails, try decrypting with Server's Master Key
        if (!decryptedCode) {
            try {
                const bytes = CryptoJS.AES.decrypt(encrypted_master_vault, REAL_MASTER_KEY, { format: CryptoJSAesJson });
                const result = bytes.toString(CryptoJS.enc.Utf8);
                if (result) decryptedCode = JSON.parse(result);
            } catch (e) {
                decryptedCode = null;
            }
        }

        // Step 3: Return Response
        if (decryptedCode) {
            // Encode to Base64 to safely transmit HTML back to the browser
            const base64Encoded = Buffer.from(decryptedCode).toString('base64');
            return res.status(200).json({ status: "success", decrypted_code: base64Encoded });
        } else {
            return res.status(401).json({ status: "error", message: "Access Denied: Invalid Key." });
        }

    } catch (error) {
        return res.status(500).json({ status: "error", message: "Internal Server Error" });
    }
}
