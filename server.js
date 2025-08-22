// server.js
// Node 18+
// npm i express morgan crypto axios https dotenv

const express = require("express");
const morgan = require("morgan");
const crypto = require("crypto");
const axios = require("axios");
const https = require("https");
require("dotenv").config();

const app = express();

/* ------------ TLS / DEV FLAGS ------------- */
const INSECURE = process.env.RAYNET_INSECURE === "true";
// jeden agent do wszystkich wyjściowych HTTPS (Raynet + Graph)
const httpsAgent = new https.Agent({ rejectUnauthorized: !INSECURE });

/* ------------ LOGI / HEALTH ------------- */
app.use(morgan(':date[iso] :method :url :status - :response-time ms'));
app.get("/health", (_, res) => res.json({ ok: true, ts: new Date().toISOString() }));

/* ------------ BODY PARSERS ------------- */
// surowe body TYLKO dla webhooka (dla weryfikacji podpisu)
app.use("/facebook/webhook", express.raw({ type: "*/*", limit: "5mb" }));
// standardowy JSON dla reszty
app.use(express.json({ limit: "2mb" }));

/* ------------ KONFIG ------------- */
const VERIFY_TOKEN      = process.env.FB_VERIFY_TOKEN || "twoj_verify_token";
const APP_SECRET        = process.env.FB_APP_SECRET || "";              // App Secret (nie token!)
const PAGE_ACCESS_TOKEN = process.env.FB_PAGE_ACCESS_TOKEN || "";       // Page token z leads_retrieval
const RAYNET_HOST       = (process.env.RAYNET_HOST || "https://eu.raynetcrm.com").replace(/\/+$/, "");
const RAYNET_INSTANCE   = process.env.RAYNET_INSTANCE || "";
const RAYNET_USER       = process.env.RAYNET_USER || "";
const RAYNET_API_KEY    = process.env.RAYNET_API_KEY || "";
const VERIFY_SIGNATURE  = (process.env.VERIFY_SIGNATURE || "false") === "true";
const RAYNET_METHOD     = (process.env.RAYNET_METHOD || "POST").toUpperCase(); // POST (domyślnie) lub PUT

app.get("/debug/config", (_, res) => {
    res.json({
        VERIFY_SIGNATURE,
        INSECURE,
        has_APP_SECRET: Boolean(APP_SECRET),
        has_PAGE_ACCESS_TOKEN: Boolean(PAGE_ACCESS_TOKEN),
        RAYNET_HOST,
        RAYNET_INSTANCE,
        RAYNET_USER: RAYNET_USER ? "set" : "missing",
        RAYNET_METHOD
    });
});

/* ------------ UTILS ------------- */
function verifySignature(req) {
    if (!VERIFY_SIGNATURE) return true; // na dev wyłączone
    const sig = req.headers["x-hub-signature-256"];
    if (!sig || !APP_SECRET) return false;
    const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.body).digest("hex");
    try {
        return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    } catch {
        return false;
    }
}

function parseFieldData(field_data = []) {
    const out = {};
    for (const f of field_data) {
        if (!f || !f.name) continue;
        out[f.name] = Array.isArray(f.values) ? f.values[0] : f.values;
    }
    return out;
}

function axErr(e) {
    return {
        message: e.message,
        code: e.code,
        url: e.config?.url,
        method: e.config?.method,
        status: e.response?.status,
        data: e.response?.data
    };
}

function objClean(o) {
    // usuń undefined/empty
    const x = JSON.parse(JSON.stringify(o));
    if (x && typeof x === "object") {
        for (const k of Object.keys(x)) {
            const v = x[k];
            if (v === null) continue;
            if (typeof v === "object" && !Array.isArray(v)) {
                const vv = objClean(v);
                if (vv && Object.keys(vv).length) x[k] = vv; else delete x[k];
            } else if (Array.isArray(v) && v.length === 0) {
                delete x[k];
            }
        }
    }
    return x;
}

/* ------------ FB: POBRANIE LEADA ------------- */
async function fbFetchLead(leadId) {
    const fields = [
        "created_time","field_data","ad_id","adgroup_id","campaign_id",
        "form_id","page_id","platform"
    ].join(",");

    // appsecret_proof = HMAC_SHA256(token, APP_SECRET)
    const appsecret_proof = APP_SECRET
        ? crypto.createHmac("sha256", APP_SECRET).update(PAGE_ACCESS_TOKEN).digest("hex")
        : null;

    const base = `https://graph.facebook.com/v23.0/${leadId}`;
    const params = new URLSearchParams({ fields, access_token: PAGE_ACCESS_TOKEN });
    if (appsecret_proof) params.set("appsecret_proof", appsecret_proof);

    const url = `${base}?${params.toString()}`;

    const resp = await axios.get(url, {
        timeout: 30000,
        httpsAgent,
        validateStatus: s => s >= 200 && s < 500,
    });

    if (resp.status >= 400 || resp.data?.error) {
        throw new Error(`[FB] ${resp.status} ${JSON.stringify(resp.data?.error || resp.data)}`);
    }
    return resp.data;
}

// === REPLACE THIS FUNCTION IN server.js ===
async function raynetCreateLead({ topic, note }) {
    // minimalny, akceptowalny payload wg RAYNET
    const payload = {
        topic: topic || "Lead z Facebook Lead Ads",
        note: note || "",
        // te dwa są wspierane i bezpieczne
        notificationMessage: "Nowy lead z Meta",
        notificationEmailAddresses: [RAYNET_USER].filter(Boolean)
    };

    const auth = Buffer.from(`${RAYNET_USER}:${RAYNET_API_KEY}`).toString("base64");
    const headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Instance-Name": RAYNET_INSTANCE,
        "Authorization": `Basic ${auth}`,
    };

    // spróbuj POST bez trailing slash -> /api/v2/lead
    const base1 = `${RAYNET_HOST}/api/v2/lead`;
    // fallback: POST/PUT z trailing slashem -> /api/v2/lead/
    const base2 = `${RAYNET_HOST}/api/v2/lead/`;

    const options = {
        timeout: 20000,
        httpsAgent,
        validateStatus: s => s >= 200 && s < 500,
        headers
    };

    // helper do jednej próby
    const tryCall = async (method, url) => {
        const resp = await axios({ method, url, data: payload, ...options });
        if (resp.status >= 400 || !resp.data || resp.data.type === "BackEnd") {
            throw new Error(`[RAYNET] ${resp.status} ${JSON.stringify(resp.data)}`);
        }
        return resp.data;
    };

    try {
        return await tryCall("post", base1);
    } catch (e1) {
        try {
            return await tryCall("post", base2);
        } catch (e2) {
            try {
                return await tryCall("put", base2);
            } catch (e3) {
                const pick = (err) => ({
                    message: err.message,
                    data: err?.response?.data, status: err?.response?.status, url: err?.config?.url
                });
                throw new Error(`CreateLead failed:\n- POST ${base1}: ${JSON.stringify(pick(e1))}\n- POST ${base2}: ${JSON.stringify(pick(e2))}\n- PUT  ${base2}: ${JSON.stringify(pick(e3))}`);
            }
        }
    }
}

/* ------------ WEBHOOK VERIFY (GET) ------------- */
app.get("/facebook/webhook", (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (mode === "subscribe" && token === VERIFY_TOKEN) {
        console.log("✅ Webhook zweryfikowany");
        return res.status(200).send(challenge);
    }
    console.warn("❌ Webhook verify failed", { mode, token_ok: token === VERIFY_TOKEN });
    return res.sendStatus(403);
});

/* ------------ IDEMPOTENCJA Z TTL ------------- */
const seen = new Map(); // leadId -> expiresAt (ts ms)
const SEEN_TTL_MS = 30 * 60 * 1000;
setInterval(() => {
    const now = Date.now();
    for (const [k, until] of seen) if (until <= now) seen.delete(k);
}, 5 * 60 * 1000);
function markSeen(leadId) { seen.set(leadId, Date.now() + SEEN_TTL_MS); }
function isSeen(leadId) { const until = seen.get(leadId); return !!(until && until > Date.now()); }

/* ------------ WEBHOOK (POST) ------------- */
app.post("/facebook/webhook", async (req, res) => {
    console.log("↘️  Webhook POST hit", {
        sig: req.headers["x-hub-signature-256"] || null,
        len: req.body?.length || 0,
        ct: req.headers["content-type"]
    });

    if (!verifySignature(req)) {
        console.warn("❌ Signature check failed");
        return res.sendStatus(403);
    }

    // Błyskawiczne ACK dla FB
    res.sendStatus(200);
    console.log("✅  200 sent to Meta (ack)");

    // Log surowego body (ułatwia debug)
    const raw = req.body?.toString?.("utf8") || "";
    console.log("📦 Raw body:", raw);

    let body;
    try {
        body = JSON.parse(raw);
    } catch (e) {
        console.error("❌ JSON parse error", e.message);
        return;
    }
    if (body.object !== "page" || !Array.isArray(body.entry)) {
        console.warn("ℹ️  Not a page webhook or no entries");
        return;
    }

    for (const entry of body.entry) {
        if (!Array.isArray(entry.changes)) continue;

        for (const change of entry.changes) {
            if (change.field !== "leadgen" || !change.value?.leadgen_id) continue;
            const leadId = change.value.leadgen_id;

            if (isSeen(leadId)) {
                console.log("ℹ️  Duplicate lead id, skipping:", leadId);
                continue;
            }
            markSeen(leadId);

            try {
                // testowe ID z /test/mock-webhook → nie wołamy Graph
                let lead;
                if (/^TEST_/i.test(leadId)) {
                    console.log("🧪 TEST lead – pomijam pobieranie z Graph API:", leadId);
                    lead = { field_data: [], form_id: change.value.form_id, platform: "test" };
                } else {
                    console.log("🔎 Fetching lead from Graph API:", leadId);
                    lead = await fbFetchLead(leadId);
                }

                const fields = parseFieldData(lead.field_data || []);
                const email = fields.email || fields.work_email || fields.business_email;
                const phone = fields.phone_number || fields.phone || fields.mobile;
                const fullName = fields.full_name || fields.name;
                const [firstName, ...rest] = (fullName || "").trim().split(/\s+/);
                const lastName = rest.join(" ");

                const topic = fullName || email || phone || `Lead ${leadId}`;
                const note = [
                    `Źródło: Facebook Lead Ads`,
                    `Lead ID: ${leadId}`,
                    `Form ID: ${lead.form_id || ""}`,
                    `Campaign: ${lead.campaign_id || ""} | Adset: ${lead.adgroup_id || ""} | Ad: ${lead.ad_id || ""}`,
                    `Platform: ${lead.platform || ""}`,
                    "",
                    "Dane formularza:",
                    ...Object.entries(fields).map(([k, v]) => `- ${k}: ${v}`)
                ].join("\n");

                const ray = await raynetCreateLead({ topic, note, email, phone, firstName, lastName });
                console.log("✅ Lead wysłany do Raynet:", leadId, "| RAYNET:", JSON.stringify(ray));

            } catch (err) {
                console.error("⚠️  FB fetch or Raynet error for", leadId, axErr(err));

                // Fallback – zapis testowego leada, gdy Graph API nie działa/ID fejkowe
                try {
                    const topic = `TEST WEBHOOK (leadgen_id: ${leadId})`;
                    const note = [
                        "UWAGA: To jest fallback – nie udało się pobrać leada z Graph API.",
                        "Surowy payload change.value:",
                        JSON.stringify(change.value, null, 2),
                    ].join("\n");

                    const ray = await raynetCreateLead({ topic, note });
                    console.log("✅ TEST lead utworzony w Raynet (fallback).", JSON.stringify(ray));
                } catch (e2) {
                    console.error("❌ Fallback to Raynet failed:", axErr(e2));
                }
            }
        }
    }
});

/* ------------ TEST/DEV ENDPOINTY ------------- */

// 1) ręczne utworzenie leada w Raynet (bez Facebooka)
app.post("/test/raynet", async (req, res) => {
    const topic = req.body?.topic || "Test z Postmana";
    const note  = req.body?.note  || "To jest ręczny test utworzenia leada w Raynet.";
    const email = req.body?.email || null;
    const phone = req.body?.phone || null;
    const firstName = req.body?.firstName || null;
    const lastName = req.body?.lastName || null;
    try {
        const out = await raynetCreateLead({ topic, note, email, phone, firstName, lastName });
        return res.json({ ok: true, raynet: out });
    } catch (e) {
        return res.status(500).json({ ok: false, error: axErr(e) });
    }
});

// 2) zasymuluj webhook FB (sample payload) — generuje poprawny format; podpisze, jeśli weryfikacja włączona
app.post("/test/mock-webhook", async (req, res) => {
    try {
        const def = {
            object: "page",
            entry: [{
                changes: [{
                    field: "leadgen",
                    value: {
                        leadgen_id: "TEST_FAKE_" + Math.floor(Math.random()*1e6),
                        form_id: "FORM_123",
                        page_id: "PAGE_123",
                        created_time: Math.floor(Date.now()/1000)
                    }
                }]
            }]
        };
        const payload = (req.body && Object.keys(req.body).length) ? req.body : def;
        const raw = JSON.stringify(payload);

        const headers = { "Content-Type": "application/json" };
        if (VERIFY_SIGNATURE && APP_SECRET) {
            const sig = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(raw).digest("hex");
            headers["x-hub-signature-256"] = sig;
        }

        const r = await axios.post("http://localhost:" + (process.env.PORT || 3000) + "/facebook/webhook", raw, { headers });
        res.json({ ok: true, status: r.status });
    } catch (e) {
        res.status(500).json({ ok: false, error: axErr(e) });
    }
});

/* ------------ START ------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Bridge listening on http://localhost:${PORT}`));
