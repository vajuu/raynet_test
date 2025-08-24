// Node 18+
// npm i express morgan axios crypto dotenv
import express from "express";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";
import https from "https";
import "dotenv/config";

const app = express();

/* ---------- ENV ---------- */
const {
    PORT = 3000,

    // Facebook
    FB_VERIFY_TOKEN,
    FB_APP_SECRET,
    FB_PAGE_TOKEN,               // long-lived PAGE token with leads_retrieval
    FB_GRAPH_VERSION = "v21.0",

    // RAYNET
    RAYNET_INSTANCE,             // e.g. "my-crm"
    RAYNET_USERNAME,             // your RAYNET user login (email)
    RAYNET_API_KEY,              // API key for that user
    RAYNET_NOTIFY = "",          // optional comma list of emails to notify
    RAYNET_OWNER_ID,             // optional RAYNET user id (owner)

    // TLS options
    INSECURE = "false"
} = process.env;

/* ---------- AXIOS ---------- */
axios.defaults.proxy = false;
const httpsAgentPublic = new https.Agent({ rejectUnauthorized: true });
const httpsAgentRaynet = new https.Agent({ rejectUnauthorized: !(INSECURE === "true") });

/* ---------- LOGS / HEALTH ---------- */
app.use(morgan(":date[iso] :method :url :status - :response-time ms"));
app.get("/health", (_, res) => res.json({ ok: true, ts: new Date().toISOString() }));

/* ---------- BODY PARSERS ---------- */
app.use("/facebook/webhook", express.raw({ type: "*/*", limit: "5mb" }));
app.use(express.json({ limit: "2mb" }));

/* ---------- FB VERIFY (GET) ---------- */
app.get("/facebook/webhook", (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];
    if (mode === "subscribe" && token === FB_VERIFY_TOKEN) return res.status(200).send(challenge);
    return res.sendStatus(403);
});

/* ---------- FB SIGNATURE VERIFY ---------- */
function verifyFacebookSignature(req) {
    const signature = req.headers["x-hub-signature-256"];
    if (!signature || !FB_APP_SECRET) return false;
    const [algo, expected] = signature.split("=");
    if (algo !== "sha256" || !expected) return false;
    const hmac = crypto.createHmac("sha256", FB_APP_SECRET);
    hmac.update(req.body); // raw Buffer
    const digest = hmac.digest("hex");
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(expected));
}

/* ---------- HELPERS ---------- */
function fieldDataToObject(field_data = []) {
    const obj = {};
    for (const { name, values } of field_data) {
        const v = Array.isArray(values) ? values[0] : values;
        obj[name] = v;
    }
    return obj;
}

/* ---------- MAPPING: FB → RAYNET ---------- */
function mapFacebookLeadToRaynetLead(fbLead) {
    const fd = fieldDataToObject(fbLead.field_data);

    // name handling
    let firstName = fd.first_name || "";
    let lastName = fd.last_name || "";
    if ((!firstName || !lastName) && fd.full_name) {
        const parts = String(fd.full_name).trim().split(/\s+/);
        firstName ||= parts.shift() || "";
        lastName ||= parts.join(" ");
    }

    const lead = {
        topic: `Facebook Lead: ${fd.topic || fbLead.form_id || "Untitled"}`,
        priority: "DEFAULT",
        firstName: firstName || undefined,
        lastName: lastName || undefined,
        companyName: fd.company_name || undefined,
        owner: RAYNET_OWNER_ID ? Number(RAYNET_OWNER_ID) : undefined,
        tags: "facebook,lead_ads",
        notice:
            `Lead Ads import\n` +
            `ad_id=${fbLead.ad_id || ""}\nform_id=${fbLead.form_id || ""}\ncreated_time=${fbLead.created_time || ""}`,
        contactInfo: {
            email: fd.email || undefined,
            tel1: fd.phone_number || undefined,
            telType: fd.phone_number ? "Mobile" : undefined,
            www: fd.website || undefined
        },
        address: {
            street: fd.street || undefined,
            city: fd.city || undefined,
            province: fd.state || undefined,
            zipCode: fd.zip_code || undefined,
            country: fd.country || undefined
        },
        notificationMessage: "New Facebook lead",
        notificationEmailAddresses: (RAYNET_NOTIFY || "")
            .split(",")
            .map(s => s.trim())
            .filter(Boolean)
    };

    // append any extra unknown fields into notice
    const known = new Set([
        "first_name","last_name","full_name","email","phone_number",
        "city","state","country","zip_code","street","company_name","website","topic"
    ]);
    const extras = Object.fromEntries(Object.entries(fd).filter(([k]) => !known.has(k)));
    if (Object.keys(extras).length) {
        lead.notice += `\nextras=${JSON.stringify(extras)}`;
    }

    return JSON.parse(JSON.stringify(lead)); // strip undefineds
}

/* ---------- RAYNET CALL ---------- */
async function createRaynetLead(leadBody) {
    const url = "https://app.raynet.cz/api/v2/lead/";
    const res = await axios.put(url, leadBody, {
        headers: {
            "X-Instance-Name": RAYNET_INSTANCE,
            "Content-Type": "application/json"
        },
        auth: { username: RAYNET_USERNAME, password: RAYNET_API_KEY },
        httpsAgent: httpsAgentRaynet,
        timeout: 15000
    });
    return res.data;
}

/* ---------- FB GRAPH CALL ---------- */
async function fetchLeadFromFacebook(leadId) {
    const url = `https://graph.facebook.com/${FB_GRAPH_VERSION}/${leadId}`;
    const params = {
        access_token: FB_PAGE_TOKEN,
        fields: "id,ad_id,form_id,created_time,field_data,custom_disclaimer_responses"
    };
    const res = await axios.get(url, { params, httpsAgent: httpsAgentPublic, timeout: 12000 });
    return res.data;
}

/* ---------- DEDUP ---------- */
const processed = new Set();

/* ---------- WEBHOOK (POST) ---------- */
app.post("/facebook/webhook", async (req, res) => {
    try {
        if (!verifyFacebookSignature(req)) return res.status(401).json({ error: "Invalid signature" });
        const body = JSON.parse(req.body.toString("utf8"));
        res.status(200).json({ ok: true }); // acknowledge early

        for (const entry of body.entry || []) {
            for (const change of entry.changes || []) {
                if (change.field !== "leadgen") continue;
                const leadId = change.value?.leadgen_id || change.value?.lead_id;
                if (!leadId || processed.has(leadId)) continue;
                processed.add(leadId);

                try {
                    const fbLead = await fetchLeadFromFacebook(leadId);
                    const raynetLead = mapFacebookLeadToRaynetLead(fbLead);
                    const created = await createRaynetLead(raynetLead);
                    console.log(`RAYNET lead created for FB lead ${leadId}:`, created?.data?.id ?? created?.id ?? "OK");
                } catch (e) {
                    if (axios.isAxiosError(e)) {
                        console.error("Bridge error:", { msg: e.message, status: e.response?.status, data: e.response?.data });
                    } else {
                        console.error("Bridge error:", e);
                    }
                }
            }
        }
    } catch (err) {
        console.error("Webhook handler failed:", err);
        if (!res.headersSent) res.sendStatus(200);
    }
});

/* ---------- START ---------- */
app.listen(PORT, () => {
    console.log(`Bridge listening on :${PORT}`);
    console.log(`INSECURE for RAYNET = ${INSECURE}`);
});
