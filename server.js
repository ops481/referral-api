import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import pg from "pg";
import nodemailer from "nodemailer";

const { Pool } = pg;

const app = express();
const db = new Pool({ connectionString: process.env.DATABASE_URL });

const WHOP_API_BASE = process.env.WHOP_API_BASE || "https://sandbox-api.whop.com/api/v1";
const WHOP_FRONTEND_BASE = process.env.WHOP_FRONTEND_BASE || "https://sandbox.whop.com";
const WHOP_PLAN_ID = process.env.WHOP_PLAN_ID;
const APP_ORIGIN = process.env.APP_ORIGIN;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
if (!process.env.WHOP_API_KEY) throw new Error("WHOP_API_KEY is required.");
if (!WHOP_PLAN_ID) throw new Error("WHOP_PLAN_ID is required.");
if (!APP_ORIGIN) throw new Error("APP_ORIGIN is required.");
if (!FRONTEND_ORIGIN) throw new Error("FRONTEND_ORIGIN is required.");
if (!SESSION_SECRET) throw new Error("SESSION_SECRET is required.");
if (!ADMIN_API_KEY) throw new Error("ADMIN_API_KEY is required.");

app.use(express.json({ limit: "1mb" }));

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: false,
  allowedHeaders: ["Content-Type", "Authorization", "X-Admin-Key"],
  methods: ["GET", "POST", "OPTIONS"]
}));

function normalizeEmail(email) {
  const clean = String(email || "").trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) {
    const err = new Error("Valid email required.");
    err.status = 400;
    throw err;
  }

  return clean;
}

function normalizeReferralCode(value) {
  return String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 32);
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function randomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function randomReferralCode() {
  return crypto
    .randomBytes(5)
    .toString("base64url")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 8);
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));

  if (!left.length || !right.length || left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function requireAdmin(req, res, next) {
  if (!safeEqual(req.get("X-Admin-Key"), ADMIN_API_KEY)) {
    return res.status(401).json({ error: "Admin key required." });
  }

  next();
}

function signAccessToken(customerId) {
  const payload = {
    sub: customerId,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 30
  };

  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

  return `${body}.${sig}`;
}

function verifyAccessToken(token) {
  const [body, sig] = String(token || "").split(".");

  if (!body || !sig) return null;

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(body)
    .digest("base64url");

  if (!safeEqual(sig, expected)) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.sub || !payload.exp || payload.exp < Date.now()) return null;
    return payload.sub;
  } catch {
    return null;
  }
}

function requireCustomer(req, res, next) {
  const auth = req.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const customerId = verifyAccessToken(token);

  if (!customerId) {
    return res.status(401).json({ error: "Please log in." });
  }

  req.customerId = customerId;
  next();
}

async function whop(path, { method = "GET", body, idempotencyKey } = {}) {
  const response = await fetch(`${WHOP_API_BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${process.env.WHOP_API_KEY}`,
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await response.text();
  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const err = new Error(data.error || data.message || `Whop API failed with ${response.status}.`);
    err.status = 502;
    err.details = data;
    throw err;
  }

  return data;
}

async function ensureCustomer(input) {
  const email = normalizeEmail(input.email);

  for (let i = 0; i < 5; i++) {
    const referralCode = randomReferralCode();

    try {
      const { rows } = await db.query(
        `
        insert into customers(email, full_name, phone, company, referral_code)
        values($1,$2,$3,$4,$5)
        on conflict(email) do update set
          full_name=coalesce(excluded.full_name, customers.full_name),
          phone=coalesce(excluded.phone, customers.phone),
          company=coalesce(excluded.company, customers.company),
          updated_at=now()
        returning *
        `,
        [
          email,
          input.full_name || null,
          input.phone || null,
          input.company || null,
          referralCode
        ]
      );

      return rows[0];
    } catch (err) {
      if (String(err.message).includes("customers_referral_code_key")) continue;
      throw err;
    }
  }

  throw new Error("Could not create referral code.");
}

function getPaymentId(payment) {
  return (
    payment.id ||
    payment.payment_id ||
    payment.payment?.id ||
    payment.data?.id ||
    null
  );
}

function getCheckoutConfigId(payment) {
  return (
    payment.checkout_configuration_id ||
    payment.checkout_config_id ||
    payment.checkoutConfigurationId ||
    payment.checkout_configuration?.id ||
    payment.checkout_config?.id ||
    payment.metadata?.whop_checkout_config_id ||
    null
  );
}

function getPaymentMetadata(payment) {
  return (
    payment.metadata ||
    payment.checkout_configuration?.metadata ||
    payment.checkout_config?.metadata ||
    payment.data?.metadata ||
    {}
  );
}

function getPaymentEmail(payment, metadata) {
  return (
    metadata.buyer_email ||
    payment.email ||
    payment.customer_email ||
    payment.member?.email ||
    payment.user?.email ||
    payment.buyer?.email ||
    null
  );
}

function getPaymentName(payment, metadata) {
  return (
    metadata.full_name ||
    payment.name ||
    payment.customer_name ||
    payment.member?.name ||
    payment.user?.name ||
    payment.buyer?.name ||
    null
  );
}

async function buildDashboard(customerId) {
  const customerResult = await db.query(
    "select * from customers where id=$1",
    [customerId]
  );

  const customer = customerResult.rows[0];

  if (!customer) {
    const err = new Error("Customer not found.");
    err.status = 404;
    throw err;
  }

  const referralResult = await db.query(
    `
    select
      r.*,
      c.full_name as friend_name,
      c.email as friend_email
    from referrals r
    join customers c on c.id = r.referred_customer_id
    where r.referrer_customer_id=$1
    order by r.created_at desc
    `,
    [customerId]
  );

  const referrals = referralResult.rows.map((r) => ({
    id: r.id,
    friend_name: r.friend_name || "Friend",
    friend_email_masked: String(r.friend_email).replace(/^(.).+(@.+)$/, "$1***$2"),
    friend_paid_at: r.friend_paid_at,
    payment_status: r.payment_status,
    refund_status: r.refund_status,
    refund_amount_cents: r.refund_amount_cents,
    currency: r.currency,
    whop_refund_id: r.whop_refund_id,
    processed_at: r.processed_at
  }));

  const paidReferrals = referrals.filter((r) => r.payment_status === "paid").length;
  const pendingReferrals = referrals.filter((r) => r.refund_status === "pending").length;
  const processedRefundCents = referrals
    .filter((r) => r.refund_status === "processed")
    .reduce((sum, r) => sum + Number(r.refund_amount_cents || 0), 0);

  return {
    customer: {
      name: customer.full_name,
      email: customer.email,
      referral_code: customer.referral_code,
      referral_link: `${APP_ORIGIN}/checkout.html?a=${encodeURIComponent(customer.referral_code)}`,
      paid_at: customer.paid_at
    },
    stats: {
      max_referrals: 2,
      paid_referrals: Math.min(paidReferrals, 2),
      pending_referrals: pendingReferrals,
      processed_refund_cents: processedRefundCents,
      total_possible_refund_cents: customer.ticket_amount_cents,
      currency: customer.currency
    },
    referrals
  };
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, environment: process.env.WHOP_ENVIRONMENT || "sandbox" });
});

app.post("/api/referrals/create-checkout", async (req, res, next) => {
  try {
    const customer = await ensureCustomer(req.body);
    const referredByCode = normalizeReferralCode(req.body.referred_by || req.body.affiliate_code);

    if (referredByCode && referredByCode === customer.referral_code) {
      return res.status(400).json({ error: "You cannot use your own referral link." });
    }

    const metadata = {
      customer_id: customer.id,
      buyer_email: customer.email,
      full_name: customer.full_name || "",
      referral_code: customer.referral_code,
      referred_by_code: referredByCode || "",
      source_url: req.body.source_url || "",
      visitor_id: req.body.visitor_id || ""
    };

    const checkout = await whop("/checkout_configurations", {
      method: "POST",
      body: {
        mode: "payment",
        plan: {
          id: WHOP_PLAN_ID
        },
        affiliate_code: referredByCode || null,
        allow_promo_codes: true,
        redirect_url: `${APP_ORIGIN}/thankyou.html`,
        source_url: req.body.source_url || APP_ORIGIN,
        metadata
      }
    });

    const checkoutId = checkout.id;
    let purchaseUrl = checkout.purchase_url;

    if (!purchaseUrl) {
      throw new Error("Whop did not return a purchase_url.");
    }

    if (purchaseUrl.startsWith("/")) {
      purchaseUrl = `${WHOP_FRONTEND_BASE}${purchaseUrl}`;
    }

    await db.query(
      `
      insert into checkout_configs(
        whop_checkout_config_id,
        customer_id,
        referred_by_code,
        metadata,
        status
      )
      values($1,$2,$3,$4,'created')
      on conflict(whop_checkout_config_id) do update set
        metadata=excluded.metadata,
        referred_by_code=excluded.referred_by_code,
        updated_at=now()
      `,
      [checkoutId, customer.id, referredByCode || null, metadata]
    );

    res.json({
      ok: true,
      checkout_id: checkoutId,
      purchase_url: purchaseUrl,
      environment: process.env.WHOP_ENVIRONMENT || "sandbox"
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/referrals/login", async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);

    const customerResult = await db.query(
      "select * from customers where email=$1 and paid_at is not null",
      [email]
    );

    const customer = customerResult.rows[0];

    if (!customer) {
      return res.json({
        ok: true,
        message: "If that booking email exists, a login link has been sent."
      });
    }

    const rawToken = randomString(32);

    await db.query(
      `
      insert into dashboard_login_tokens(customer_id, token_hash, expires_at)
      values($1,$2,now()+interval '30 minutes')
      `,
      [customer.id, sha256(rawToken)]
    );

    const loginLink = `${APP_ORIGIN}/thankyou.html?token=${encodeURIComponent(rawToken)}`;

    if (process.env.SMTP_URL) {
      const transport = nodemailer.createTransport(process.env.SMTP_URL);

      await transport.sendMail({
        to: customer.email,
        from: process.env.MAIL_FROM || "test@example.com",
        subject: "Your Monaco referral dashboard login",
        text: `Open your referral dashboard here: ${loginLink}`
      });
    } else {
      console.log("MAGIC LOGIN LINK:", loginLink);
    }

    res.json({
      ok: true,
      message: "Check your email for your secure dashboard link. In sandbox without SMTP, check Render logs.",
      debug_login_link: process.env.SMTP_URL ? undefined : loginLink
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/referrals/session", async (req, res, next) => {
  try {
    const token = String(req.body.token || "");
    const tokenHash = sha256(token);

    const result = await db.query(
      `
      update dashboard_login_tokens
      set used_at=now()
      where token_hash=$1
        and used_at is null
        and expires_at > now()
      returning customer_id
      `,
      [tokenHash]
    );

    const row = result.rows[0];

    if (!row) {
      return res.status(401).json({ error: "Login link expired or already used." });
    }

    res.json({
      ok: true,
      access_token: signAccessToken(row.customer_id)
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/referrals/me", requireCustomer, async (req, res, next) => {
  try {
    res.json(await buildDashboard(req.customerId));
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/referrals/refund-queue", requireAdmin, async (_req, res, next) => {
  try {
    const result = await db.query(
      `
      select
        r.*,
        referrer.full_name as referrer_name,
        referrer.email as referrer_email,
        referrer.referral_code as referrer_referral_code,
        referrer.whop_payment_id as referrer_whop_payment_id,
        friend.full_name as friend_name,
        friend.email as friend_email
      from referrals r
      join customers referrer on referrer.id = r.referrer_customer_id
      join customers friend on friend.id = r.referred_customer_id
      where r.refund_status in ('pending','failed')
      order by r.created_at asc
      `
    );

    res.json({ referrals: result.rows });
  } catch (err) {
    next(err);
  }
});

app.post("/api/admin/referrals/:id/approve-refund", requireAdmin, async (req, res, next) => {
  const client = await db.connect();

  try {
    await client.query("begin");

    const result = await client.query(
      `
      select
        r.*,
        c.whop_payment_id as referrer_whop_payment_id,
        c.ticket_amount_cents as referrer_ticket_amount_cents
      from referrals r
      join customers c on c.id = r.referrer_customer_id
      where r.id=$1
      for update
      `,
      [req.params.id]
    );

    const referral = result.rows[0];

    if (!referral) {
      const err = new Error("Referral not found.");
      err.status = 404;
      throw err;
    }

    if (referral.refund_status === "processed") {
      const err = new Error("Refund already processed.");
      err.status = 409;
      throw err;
    }

    if (referral.payment_status !== "paid") {
      const err = new Error("Friend has not paid yet.");
      err.status = 400;
      throw err;
    }

    if (!referral.referrer_whop_payment_id) {
      const err = new Error("Referrer payment ID missing. Cannot refund.");
      err.status = 400;
      throw err;
    }

    const alreadyApprovedResult = await client.query(
      `
      select count(*)::int as count
      from referrals
      where referrer_customer_id=$1
        and refund_status='processed'
      `,
      [referral.referrer_customer_id]
    );

    if (alreadyApprovedResult.rows[0].count >= 2) {
      const err = new Error("This referrer has already received the maximum 2 referral refunds.");
      err.status = 400;
      throw err;
    }

    const amountCents = Math.min(
      Number(req.body.amount_cents || referral.refund_amount_cents),
      130000
    );

    if (!Number.isInteger(amountCents) || amountCents <= 0) {
      const err = new Error("Invalid refund amount.");
      err.status = 400;
      throw err;
    }

    const idempotencyKey = `referral-refund-${referral.id}-${amountCents}`;

    await client.query(
      `
      update referrals
      set refund_status='processing',
          idempotency_key=$2,
          admin_note=$3,
          updated_at=now()
      where id=$1
      `,
      [referral.id, idempotencyKey, req.body.admin_note || null]
    );

    await client.query("commit");

    const whopRefundResponse = await whop(
      `/payments/${encodeURIComponent(referral.referrer_whop_payment_id)}/refund`,
      {
        method: "POST",
        idempotencyKey,
        body: {
          partial_amount: amountCents / 100
        }
      }
    );

    const refundId =
      whopRefundResponse.refund?.id ||
      whopRefundResponse.refund_id ||
      whopRefundResponse.id ||
      null;

    await db.query(
      `
      update referrals
      set refund_status='processed',
          whop_refund_id=$2,
          processed_at=now(),
          updated_at=now()
      where id=$1
      `,
      [referral.id, refundId]
    );

    res.json({
      ok: true,
      whop_refund_id: refundId,
      whop_response: whopRefundResponse
    });
  } catch (err) {
    try {
      await client.query("rollback");
    } catch {}

    try {
      await db.query(
        `
        update referrals
        set refund_status='failed',
            updated_at=now()
        where id=$1
          and refund_status='processing'
        `,
        [req.params.id]
      );
    } catch {}

    next(err);
  } finally {
    client.release();
  }
});

app.post("/api/admin/referrals/:id/decline-refund", requireAdmin, async (req, res, next) => {
  try {
    await db.query(
      `
      update referrals
      set refund_status='declined',
          admin_note=$2,
          updated_at=now()
      where id=$1
        and refund_status <> 'processed'
      `,
      [req.params.id, req.body.admin_note || null]
    );

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

app.post("/api/whop/webhook", async (req, res, next) => {
  try {
    const event = req.body || {};
    const eventId = event.id || event.event_id || sha256(JSON.stringify(event));
    const eventType = event.type || event.event_type;

    await db.query(
      `
      insert into whop_webhook_events(id, event_type, payload)
      values($1,$2,$3)
      on conflict(id) do nothing
      `,
      [eventId, eventType || "unknown", event]
    );

    if (eventType === "payment.succeeded") {
      const payment = event.data || event.payment || event;
      const metadata = getPaymentMetadata(payment);
      const paymentId = getPaymentId(payment);
      const checkoutConfigId = getCheckoutConfigId(payment);
      const email = getPaymentEmail(payment, metadata);
      const name = getPaymentName(payment, metadata);

      if (!paymentId || !email) {
        console.log("payment.succeeded missing paymentId/email", { paymentId, email, event });
        return res.json({ ok: true, skipped: true });
      }

      const customer = await ensureCustomer({
        email,
        full_name: name
      });

      await db.query(
        `
        update customers
        set whop_payment_id=$2,
            whop_checkout_config_id=coalesce($3, whop_checkout_config_id),
            paid_at=coalesce($4, now()),
            updated_at=now()
        where id=$1
        `,
        [
          customer.id,
          paymentId,
          checkoutConfigId,
          payment.paid_at || payment.created_at || null
        ]
      );

      if (checkoutConfigId) {
        await db.query(
          `
          update checkout_configs
          set status='paid',
              updated_at=now()
          where whop_checkout_config_id=$1
          `,
          [checkoutConfigId]
        );
      }

      const referredByCode = normalizeReferralCode(
        metadata.referred_by_code ||
        metadata.affiliate_code ||
        ""
      );

      if (referredByCode && referredByCode !== customer.referral_code) {
        const referrerResult = await db.query(
          "select * from customers where referral_code=$1 and paid_at is not null",
          [referredByCode]
        );

        const referrer = referrerResult.rows[0];

        if (referrer) {
          const currentRewardCount = await db.query(
            `
            select count(*)::int as count
            from referrals
            where referrer_customer_id=$1
              and refund_status <> 'declined'
            `,
            [referrer.id]
          );

          if (currentRewardCount.rows[0].count < 2) {
            await db.query(
              `
              insert into referrals(
                referrer_customer_id,
                referred_customer_id,
                friend_whop_payment_id,
                friend_paid_at,
                refund_amount_cents,
                currency,
                payment_status,
                refund_status
              )
              values($1,$2,$3,coalesce($4,now()),130000,'EUR','paid','pending')
              on conflict do nothing
              `,
              [
                referrer.id,
                customer.id,
                paymentId,
                payment.paid_at || payment.created_at || null
              ]
            );
          }
        }
      }
    }

    if (eventType === "refund.created" || eventType === "refund.updated") {
      const refund = event.data || event.refund || event;
      const refundId = refund.id || refund.refund_id;

      if (refundId) {
        await db.query(
          `
          update referrals
          set whop_refund_id=coalesce(whop_refund_id, $1),
              refund_status='processed',
              processed_at=coalesce(processed_at, now()),
              updated_at=now()
          where whop_refund_id=$1
          `,
          [refundId]
        );
      }
    }

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);

  res.status(err.status || 500).json({
    error: err.message || "Server error.",
    details: err.details
  });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Referral API running on port ${port}`);
});