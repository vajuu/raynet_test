import express from "express";
import axios from "axios";
import crypto from "crypto";
import morgan from "morgan";
import https from "https";
import "dotenv/config";

const app = express();

const INSECURE = process.env.INSECURE === "true";
const httpsAgent = new https.Agent({ rejectUnauthorized: !INSECURE });

// 👇 log i globalny fallback (DEV only)
if (INSECURE) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // awaryjny pas bezpieczeństwa
}
console.log(`Bridge starting… INSECURE=${INSECURE}`);

// 👇 JEŚLI środowisko ma proxy – wyłącz je dla axios (ważne)
axios.defaults.proxy = false;

app.use(morgan(':date[iso] :method :url :status - :response-time ms'));
app.get("/health", (_, res) => res.json({ ok: true, insecure: INSECURE, ts: new Date().toISOString() }));

app.use("/facebook/webhook", express.raw({ type: "*/*", limit: "5mb" }));
app.use(express.json({ limit: "2mb" }));

const {
    PORT = 3000,
    FB_VERIFY_TOKEN,
    FB_APP_SECRET,
    FB_PAGE_TOKEN,
    RAYNET_INSTANCE,
    RAYNET_USERNAME,
    RAYNET_API_KEY
} = process.env;

function verifyFacebookSignature(req) {
    const signature = req.headers["x-hub-signature-256"];
    if (!signature || !FB_APP_SECRET) return false;
    const hmac = crypto.createHmac("sha256", FB_APP_SECRET);
    hmac.update(req.body);
    const expected = "sha256=" + hmac.digest("hex");
    const a = Buffer.from(String(signature));
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

app.get("/facebook/webhook", (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];
    if (mode === "subscribe" && token === FB_VERIFY_TOKEN) return res.status(200).send(challenge);
    return res.sendStatus(403);
});

app.post("/facebook/webhook", async (req, res) => {
    try {
        if (!verifyFacebookSignature(req)) return res.sendStatus(403);

        const body = JSON.parse(req.body.toString("utf8"));

        for (const entry of body.entry ?? []) {
            for (const change of entry.changes ?? []) {
                if (change.field !== "leadgen") continue;

                const leadId = change.value?.leadgen_id;
                const formId = change.value?.form_id;
                if (!leadId) continue;

                // --- Graph API
                const graph = await axios.get(`https://graph.facebook.com/v23.0/${leadId}`, {
                    params: {
                        access_token: FB_PAGE_TOKEN,
                        fields: "created_time,ad_id,form_id,field_data,custom_disclaimer_responses"
                    },
                    timeout: 15000,
                    httpsAgent,
                    proxy: false,               // <— KLUCZOWE
                });

                const fbLead = graph.data;
                const kv = Object.fromEntries(
                    (fbLead.field_data || []).map(f => [f.name, (f.values || [])[0] || ""])
                );

                let firstName = kv.first_name || "";
                let lastName = kv.last_name || "";
                if ((!firstName || !lastName) && kv.full_name) {
                    const parts = kv.full_name.trim().split(/\s+/);
                    firstName = firstName || parts[0] || "";
                    lastName = lastName || parts.slice(1).join(" ") || "";
                }

                const leadPayload = {
                    topic: `FB Lead: ${kv.full_name || kv.name || kv.email || leadId}`,
                    firstName,
                    lastName,
                    email: kv.email || "",
                    phone: kv.phone_number || kv.phone || "",
                    note: [
                        `Źródło: Facebook Lead Ads`,
                        `Lead ID: ${leadId}`,
                        formId ? `Form ID: ${formId}` : null,
                        fbLead.ad_id ? `Ad ID: ${fbLead.ad_id}` : null
                    ].filter(Boolean).join("\n"),
                };

                // --- Raynet
                const created = await createRaynetLead(leadPayload);
                console.log("RAYNET Lead created:", created?.id || created);
            }
        }

        res.sendStatus(200);
    } catch (err) {
        console.error("Webhook error:", {
            message: err?.message,
            code: err?.code,
            errno: err?.errno,
            syscall: err?.syscall,
            status: err?.response?.status,
            data: err?.response?.data
        });
        res.sendStatus(500);
    }
});

async function createRaynetLead(data) {
    const base = `https://${RAYNET_INSTANCE}.raynetcrm.com/api/v2`;
    const url = `${base}/leads`;
    const auth = Buffer.from(`${RAYNET_USERNAME}:${RAYNET_API_KEY}`).toString("base64");

    const resp = await axios.post(url, data, {
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Basic ${auth}`
        },
        timeout: 15000,
        httpsAgent,
        proxy: false,                   // <— KLUCZOWE
    });

    return resp.data;
}

app.listen(PORT, () => {
    console.log(`Bridge listening on :${PORT} (INSECURE=${INSECURE})`);
});
