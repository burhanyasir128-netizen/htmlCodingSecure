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
    // APKI SECURE MASTER KEY
    // ==========================================
    const REAL_MASTER_KEY = "Yasir123";

    try {
        const { action } = req.body;

        // ----------------------------------------------------
        // ACTION 1: COMPILE
        // ----------------------------------------------------
        if (action === 'compile') {
            const { code, access_key } = req.body;
            if (!code || !access_key) return res.status(400).json({ status: "error", message: "Code and Access Key required." });
            
            const encrypted_code = CryptoJS.AES.encrypt(JSON.stringify(code), access_key, { format: CryptoJSAesJson }).toString();
            const server_token = CryptoJS.AES.encrypt(access_key, REAL_MASTER_KEY).toString();

            return res.status(200).json({ status: "success", encrypted_code, server_token });
        }

        // ----------------------------------------------------
        // ACTION 2: AUTORUN
        // ----------------------------------------------------
        else if (action === 'autorun') {
            const { encrypted_code, server_token, timestamp, browser_fingerprint } = req.body;

            const ua = req.headers['user-agent'] || '';
            if (ua.includes('Postman') || ua.includes('curl') || ua.includes('python') || ua.includes('node') || ua === '') {
                return res.status(403).json({ status: "error", message: "Security Alert: Bot or Script Detected. Access Denied." });
            }

            const currentTime = Date.now();
            if (!timestamp || Math.abs(currentTime - timestamp) > 30000) {
                return res.status(403).json({ status: "error", message: "Security Alert: Request Expired. Replay Attack Blocked." });
            }

            if (!browser_fingerprint || browser_fingerprint.length < 10) {
                return res.status(403).json({ status: "error", message: "Security Alert: Invalid Browser Environment." });
            }

            if (!encrypted_code || !server_token) return res.status(400).json({ status: "error", message: "Missing payload or token." });

            let decryptedCode = null;
            let extracted_access_key = null;
            
            try {
                const tokenBytes = CryptoJS.AES.decrypt(server_token, REAL_MASTER_KEY);
                extracted_access_key = tokenBytes.toString(CryptoJS.enc.Utf8);
            } catch (e) { return res.status(401).json({ status: "error", message: "Invalid Token." }); }

            try {
                const codeBytes = CryptoJS.AES.decrypt(encrypted_code, extracted_access_key, { format: CryptoJSAesJson });
                const result = codeBytes.toString(CryptoJS.enc.Utf8);
                if (result) decryptedCode = JSON.parse(result);
            } catch (e) { decryptedCode = null; }

            if (decryptedCode) {
                const base64Encoded = Buffer.from(decryptedCode, 'utf-8').toString('base64');
                return res.status(200).json({ status: "success", decrypted_code: base64Encoded });
            } else {
                return res.status(401).json({ status: "error", message: "Cloud Decryption Failed." });
            }
        } 
        
        // ----------------------------------------------------
        // ACTION 3: EXTRACT MASTER (Updated Logic)
        // ----------------------------------------------------
        else if (action === 'extract_master') {
            const { encrypted_code, server_token, user_key } = req.body;

            if (!encrypted_code || !server_token || !user_key) {
                return res.status(400).json({ status: "error", message: "Missing payload data." });
            }

            // Sirf us waqt khulega jab EXACT Master Key match karegi
            if (user_key === REAL_MASTER_KEY) {
                try {
                    // 1. Token ko Master Key se kholen
                    const tokenBytes = CryptoJS.AES.decrypt(server_token, REAL_MASTER_KEY);
                    const extracted_access_key = tokenBytes.toString(CryptoJS.enc.Utf8);

                    if (!extracted_access_key) throw new Error("Invalid Server Token");

                    // 2. Token ke andar chupi hui Access Key se Code kholen
                    const codeBytes = CryptoJS.AES.decrypt(encrypted_code, extracted_access_key, { format: CryptoJSAesJson });
                    const result = codeBytes.toString(CryptoJS.enc.Utf8);
                    
                    if (result) {
                        const parsedCode = JSON.parse(result);
                        const base64Encoded = Buffer.from(parsedCode, 'utf-8').toString('base64');
                        return res.status(200).json({ status: "success", decrypted_code: base64Encoded });
                    } else {
                        throw new Error("Code Decryption Failed");
                    }
                } catch (e) {
                    return res.status(500).json({ status: "error", message: "Server Decryption Error: " + e.message });
                }
            }
            return res.status(401).json({ status: "error", message: "Access Denied: Invalid Master Key." });
        }
        else {
            return res.status(400).json({ status: "error", message: "Invalid action." });
        }

    } catch (error) {
        return res.status(500).json({ status: "error", message: "Internal Server Error" });
    }
}
