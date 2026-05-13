const CryptoJS = require("crypto-js");

// Formatting for perfect Frontend <-> Backend synchronization
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
    // 1. CORS Headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ status: "error", message: "Method Not Allowed" });

    // ==========================================
    // APKI SECURE MASTER KEY (Sirf Server Par)
    // ==========================================
    const REAL_MASTER_KEY = "Yasir123";

    try {
        const { action } = req.body;

        // ----------------------------------------------------
        // ACTION 1: COMPILE (Generate Secure Token & Vault)
        // ----------------------------------------------------
        if (action === 'compile') {
            const { code, access_key } = req.body;
            if (!code || !access_key) return res.status(400).json({ status: "error", message: "Code and Access Key required." });
            
            // 1. Code ko User ki Access Key se encrypt karein
            const encrypted_code = CryptoJS.AES.encrypt(JSON.stringify(code), access_key, { format: CryptoJSAesJson }).toString();
            
            // 2. Access Key ko Master Key se lock kar ke Token banayen (Ab Access Key file mein nahi jayegi)
            const server_token = CryptoJS.AES.encrypt(access_key, REAL_MASTER_KEY).toString();

            return res.status(200).json({ status: "success", encrypted_code, server_token });
        }

        // ----------------------------------------------------
        // ACTION 2: AUTORUN (Cloud Decryption for Client File)
        // ----------------------------------------------------
        else if (action === 'autorun') {
            const { encrypted_code, server_token } = req.body;

            if (!encrypted_code || !server_token) {
                return res.status(400).json({ status: "error", message: "Missing payload or token." });
            }

            let decryptedCode = null;

            // A. Server Token ko Master Key se khol kar asli Access Key nikalen
            let extracted_access_key = null;
            try {
                const tokenBytes = CryptoJS.AES.decrypt(server_token, REAL_MASTER_KEY);
                extracted_access_key = tokenBytes.toString(CryptoJS.enc.Utf8);
            } catch (e) { return res.status(401).json({ status: "error", message: "Tampered or Invalid Server Token." }); }

            // B. Asli Access Key se Code ko decrypt karein
            try {
                const codeBytes = CryptoJS.AES.decrypt(encrypted_code, extracted_access_key, { format: CryptoJSAesJson });
                const result = codeBytes.toString(CryptoJS.enc.Utf8);
                if (result) decryptedCode = JSON.parse(result);
            } catch (e) { decryptedCode = null; }

            // C. Return Base64 Encoded Result
            if (decryptedCode) {
                const base64Encoded = Buffer.from(decryptedCode).toString('base64');
                return res.status(200).json({ status: "success", decrypted_code: base64Encoded });
            } else {
                return res.status(401).json({ status: "error", message: "Cloud Decryption Failed." });
            }
        } 
        else {
            return res.status(400).json({ status: "error", message: "Invalid action." });
        }

    } catch (error) {
        return res.status(500).json({ status: "error", message: "Internal Server Error" });
    }
}
