// server.js
// Node 18+
// npm i express morgan crypto axios https dotenv

import express from "express";
import morgan from "morgan";
import crypto from "crypto";
import axios from "axios";
import https from "https";
import "dotenv/config";

const app = express();

/* ------------ TLS / AGENTS ------------- */
// INSECURE=true -> pozwól Raynet DEV na self-signed (TYLKO Raynet!)
const INSECURE = process.env.INSECURE === "true";

// restrykcyjny agent do usług publicznych (Graph itp.)
const httpsAgentStrict = new https.Agent({ rejectUnauthorized: true });

// luzacki agent wyłącznie do Raynet DEV
const httpsAgentRaynet = new https.Agent({ rejectUnauthorized: !INSECURE });

/* ------------ AXIOS GLOBAL ------------- */
// wyłącz systemowy proxy (częsta przyczyna błędów certów)
axios.defaults.proxy = false;

console.log(`Bridge starting… INSECURE=${INSECURE}`);

/* ------------ LOGI / HEALTH ------------- */
app.use(morgan(':date[iso] :method :url :status - :response-time ms'));
app.get("/health", (_, res) => res.json({ ok: true, insecure: INSECURE, ts: new Date().toISOString() }));

/* ------------ BODY PARSERS ------------- */
// surowe body TYLKO dla webhooka (weryfikacja podpisu wymaga raw)
app.use("/facebook/webhook", express.raw({ type: "*/*", limit: "5mb" }));
// standardowy JSON dla reszty
app.use(express.json({ limit: "2mb" }));

/* ------------ KONFIG ------------- */
const {
    PORT = 3000,
    FB_VERIFY_TOKEN,
    FB_APP_SECRET,
    FB_PAGE_TOKEN,
    RAYNET_INSTANCE,   // np. "mojafirma" (bez https:// i bez sufiksu)
    RAYNET_USERNAME,
    RAYNET_API_KEY
} = process.env;

function axErr(e) {
    return {
        message: e?.message,
        code: e?.code,
        errno: e?.errno,
        syscall: e?.syscall,
        url: e?.config?.url,
        method: e?.config?.method,
        status: e?.response?.status,
        data: e?.response?.data
    };
}

/* ------------ FB: WERYFIKACJA PODPISU ------------- */
function verifyFacebookSignature(req) {
    const signature = req.headers["x-hub-signature-256"];
    if (!signature || !FB_APP_SECRET) return false;
    const expected = "sha256=" + crypto.createHmac("sha256", FB_APP_SECRET).update(req.body).digest("hex");

    const a = Buffer.from(String(signature));
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    try { return crypto.timingSafeEqual(a, b); } catch { return false; }
}

/* ------------ FB: VERIFY (GET) ------------- */
app.get("/facebook/webhook", (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];
    if (mode === "subscribe" && token === FB_VERIFY_TOKEN) return res.status(200).send(challenge);
    return res.sendStatus(403);
});

/* ------------ UTILS ------------- */
function parseFieldData(field_data = []) {
    const kv = {};
    for (const f of field_data) {
        if (!f || !f.name) continue;
        kv[f.name] = Array.isArray(f.values) ? (f.values[0] ?? "") : (f.values ?? "");
    }
    return kv;
}

/* ------------ FB: POBRANIE LEADA ------------- */
async function fbFetchLead(leadId) {
    // appsecret_proof = HMAC_SHA256(PAGE_TOKEN, APP_SECRET)
    const appsecret_proof = (FB_APP_SECRET && FB_PAGE_TOKEN)
        ? crypto.createHmac("sha256", FB_APP_SECRET).update(FB_PAGE_TOKEN).digest("hex")
        : undefined;

    const params = {
        access_token: FB_PAGE_TOKEN,
        fields: "created_time,ad_id,adgroup_id,campaign_id,form_id,field_data,custom_disclaimer_responses,platform",
        ...(appsecret_proof ? { appsecret_proof } : {})
    };

    const url = `https://graph.facebook.com/v23.0/${encodeURIComponent(leadId)}`;
    const resp = await axios.get(url, {
        params,
        timeout: 15000,
        httpsAgent: httpsAgentStrict, // ważne: restrykcyjny agent do Graph
        proxy: false,
        validateStatus: s => s >= 200 && s < 500
    });

    if (resp.status >= 400 || resp.data?.error) {
        throw new Error(`[FB] ${resp.status} ${JSON.stringify(resp.data?.error || resp.data)}`);
    }
    return resp.data;
}

/* ------------ RAYNET: UTWORZENIE LEADA (z fallbackami) ------------- */
async function createRaynetLead(data) {
    const payload = {
        topic: data.topic || "Lead z Facebook Lead Ads",
        note: data.note || "",
        firstName: data.firstName || undefined,
        lastName: data.lastName || undefined,
        email: data.email || undefined,
        phone: data.phone || undefined,
        notificationMessage: "Nowy lead z Meta",
        notificationEmailAddresses: [RAYNET_USERNAME].filter(Boolean)
    };

    const auth = Buffer.from(`${RAYNET_USERNAME}:${RAYNET_API_KEY}`).toString("base64");
    const headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Instance-Name": RAYNET_INSTANCE,
        "Authorization": `Basic ${auth}`
    };

    const baseInst = `https://${RAYNET_INSTANCE}.raynetcrm.com/api/v2`;
    const baseEu   = `https://eu.raynetcrm.com/api/v2`;

    const options = {
        timeout: 20000,
        httpsAgent: httpsAgentRaynet, // <- luzacki agent tylko tutaj
        proxy: false,
        validateStatus: s => s >= 200 && s < 500,
        headers
    };

    const endpoints = [
        { method: "post", url: `${baseInst}/lead` },
        { method: "post", url: `${baseInst}/lead/` },
        { method: "put",  url: `${baseInst}/lead/` },
        { method: "post", url: `${baseEu}/lead` },
        { method: "post", url: `${baseEu}/lead/` },
        { method: "put",  url: `${baseEu}/lead/` },
    ];

    const errors = [];
    for (const ep of endpoints) {
        try {
            const resp = await axios({ ...ep, data: payload, ...options });
            if (resp.status < 400 && resp.data && resp.data.type !== "BackEnd") {
                return resp.data;
            }
            errors.push({ ep, status: resp.status, data: resp.data });
        } catch (e) {
            errors.push({ ep, error: axErr(e) });
        }
    }
    throw new Error(`Raynet create lead failed: ${JSON.stringify(errors)}`);
}

/* ------------ IDEMPOTENCJA NA LEAD_ID ------------- */
const seen = new Map(); // leadId -> expiresAt (ms)
const SEEN_TTL_MS = 30 * 60 * 1000;
setInterval(() => {
    const now = Date.now();
    for (const [k, until] of seen) if (until <= now) seen.delete(k);
}, 5 * 60 * 1000);
const markSeen = id => seen.set(id, Date.now() + SEEN_TTL_MS);
const isSeen   = id => {
    const until = seen.get(id);
    return !!(until && until > Date.now());
};

/* ------------ WEBHOOK (POST) ------------- */
app.post("/facebook/webhook", async (req, res) => {
    // szybkie ACK do Meta, żeby nie timeoutowało
    res.sendStatus(200);

    try {
        if (!verifyFacebookSignature(req)) {
            console.warn("❌ Signature check failed");
            return;
        }

        const raw = req.body?.toString?.("utf8") || "";
        let body;
        try { body = JSON.parse(raw); } catch { console.error("❌ JSON parse error"); return; }

        if (body.object !== "page" || !Array.isArray(body.entry)) {
            console.log("ℹ️ Not a page webhook or no entries");
            return;
        }

        for (const entry of body.entry) {
            for (const change of entry.changes ?? []) {
                if (change.field !== "leadgen") continue;

                const leadId = change.value?.leadgen_id;
                const formId = change.value?.form_id;

                if (!leadId) continue;
                if (isSeen(leadId)) { console.log("ℹ️ Duplicate lead id, skipping:", leadId); continue; }
                markSeen(leadId);

                try {
                    const fbLead = await fbFetchLead(leadId);
                    const kv = parseFieldData(fbLead.field_data || []);

                    let firstName = kv.first_name || "";
                    let lastName  = kv.last_name || "";
                    if ((!firstName || !lastName) && kv.full_name) {
                        const parts = kv.full_name.trim().split(/\s+/);
                        firstName = firstName || parts[0] || "";
                        lastName  = lastName || parts.slice(1).join(" ") || "";
                    }

                    const topic = `FB Lead: ${kv.full_name || kv.name || kv.email || leadId}`;
                    const note = [
                        `Źródło: Facebook Lead Ads`,
                        `Lead ID: ${leadId}`,
                        formId ? `Form ID: ${formId}` : null,
                        fbLead.campaign_id ? `Campaign ID: ${fbLead.campaign_id}` : null,
                        fbLead.adgroup_id ? `Adset ID: ${fbLead.adgroup_id}` : null,
                        fbLead.ad_id ? `Ad ID: ${fbLead.ad_id}` : null,
                        fbLead.platform ? `Platform: ${fbLead.platform}` : null
                    ].filter(Boolean).join("\n");

                    const created = await createRaynetLead({
                        topic,
                        note,
                        firstName,
                        lastName,
                        email: kv.email || "",
                        phone: kv.phone_number || kv.phone || ""
                    });

                    console.log("✅ RAYNET Lead created:", JSON.stringify(created));

                } catch (e) {
                    console.error("⚠️ Lead processing error:", axErr(e));
                }
            }
        }
    } catch (err) {
        console.error("Webhook fatal error:", axErr(err));
    }
});

/* ------------ START ------------- */
app.listen(Number(PORT), () => {
    console.log(`🚀 Bridge listening on http://localhost:${PORT} (INSECURE=${INSECURE})`);
});
