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
    // APKI SECURE MASTER KEY (Sirf yahan server par rahegi)
    // ==========================================
    const REAL_MASTER_KEY = "Yasir123";

    try {
        const { action } = req.body;

        // ----------------------------------------------------
        // ACTION 1: LOCK (Jab client compile kar raha ho)
        // ----------------------------------------------------
        if (action === 'lock') {
            const { code } = req.body;
            if (!code) return res.status(400).json({ status: "error", message: "Code required for master locking." });
            
            // Server code ko apni Master Key se lock karta hai
            const eM = CryptoJS.AES.encrypt(JSON.stringify(code), REAL_MASTER_KEY, { format: CryptoJSAesJson }).toString();
            return res.status(200).json({ status: "success", encrypted_master_vault: eM });
        }

        // ----------------------------------------------------
        // ACTION 2: EXTRACT (Jab client extract kar raha ho)
        // ----------------------------------------------------
        else if (action === 'extract') {
            const { encrypted_auth_vault, encrypted_master_vault, user_key } = req.body;

            if (!encrypted_auth_vault || !encrypted_master_vault || !user_key) {
                return res.status(400).json({ status: "error", message: "Missing payload parameters" });
            }

            let decryptedCode = null;

            // A. Pehle User ki Access Key try karein
            try {
                const bytes = CryptoJS.AES.decrypt(encrypted_auth_vault, user_key, { format: CryptoJSAesJson });
                const result = bytes.toString(CryptoJS.enc.Utf8);
                if (result) decryptedCode = JSON.parse(result);
            } catch (e) { decryptedCode = null; }

            // B. Agar fail ho, aur user ne MASTER KEY dali ho, to Master Vault kholne ki koshish karein
            if (!decryptedCode && user_key === REAL_MASTER_KEY) {
                try {
                    const bytes = CryptoJS.AES.decrypt(encrypted_master_vault, REAL_MASTER_KEY, { format: CryptoJSAesJson });
                    const result = bytes.toString(CryptoJS.enc.Utf8);
                    if (result) decryptedCode = JSON.parse(result);
                } catch (e) { decryptedCode = null; }
            }

            // Return Result
            if (decryptedCode) {
                const base64Encoded = Buffer.from(decryptedCode).toString('base64');
                return res.status(200).json({ status: "success", decrypted_code: base64Encoded });
            } else {
                return res.status(401).json({ status: "error", message: "Access Denied: Invalid Access Key or Master Key." });
            }
        } 
        else {
            return res.status(400).json({ status: "error", message: "Invalid action." });
        }

    } catch (error) {
        return res.status(500).json({ status: "error", message: "Internal Server Error" });
    }
}
