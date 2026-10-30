require('dotenv').config();
const { Pool } = require("pg");
const express = require("express");
const path = require("path");
const { auth } = require('express-openid-connect');
const { randomUUID } = require("crypto");
const QRCode = require("qrcode");
const { auth: jwtAuth, requiredScopes } = require("express-oauth2-jwt-bearer");

const db = new Pool({
    connectionString: process.env.DATABASE_URL
});

const app = express();

app.set("view engine", "ejs");
app.set("views", __dirname);
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded());

app.use(
    auth({
        authRequired: false,
        auth0Logout: true,
        secret: process.env.OIDC_SECRET,
        baseURL: process.env.BASE_URL,
        clientID: process.env.OIDC_CLIENT_ID,
        issuerBaseURL: process.env.OIDC_ISSUER_BASE_URL,
        clientSecret: process.env.OIDC_CLIENT_SECRET
    })
);

app.get("/", async (req, res, next) => {
    try {
        const passesCountsResult = await db.query(`
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'ACTIVE') AS active
            FROM pass
        `);

        let passes = [];

        if (req.oidc.isAuthenticated()) {
            const passesResult = await db.query(`
                SELECT id, name, document, issued_at, status
                FROM pass
            `);

            passes = passesResult.rows;
        }

        res.render("index", {
            total: passesCountsResult.rows[0].total,
            active: passesCountsResult.rows[0].active,
            user: req.oidc.user || null,
            passes
        });
    }
    catch (err) {
        next(err);
    }
});

app.get("/info/:id", async (req, res, next) => {
    try {
        const passResult = await db.query(
            `
                SELECT id, name, document, issued_at, status
                FROM pass
                WHERE id = $1
            `,
            [req.params.id]
        );

        if (passResult.rows.length === 0) {
            return res.sendStatus(404);
        }

        res.render("pass", {
            pass: passResult.rows[0]
        });
    }
    catch (err) {
        next(err);
    }
});

app.post("/passes/:id/status", async (req, res, next) => {
    if (!req.oidc.isAuthenticated()) {
        return res.redirect("/login");
    }

    try {
        await db.query(
            `
                UPDATE pass
                SET status = 
                    CASE
                        WHEN status = 'ACTIVE' THEN 'CANCELLED'
                        ELSE 'ACTIVE'
                    END
                WHERE id = $1
            `,
            [req.params.id]
        );

        res.redirect("/");
    }
    catch (err) {
        next(err);
    }
});

app.post("/passes/:id/delete", async (req, res, next) => {
    if (!req.oidc.isAuthenticated()) {
        return res.redirect("/login");
    }

    try {
        await db.query(
            `DELETE FROM pass WHERE id = $1`,
            [req.params.id]
        );

        res.redirect("/");
    }
    catch (err) {
        next(err);
    }
});

const jwtCheck = jwtAuth({
    audience: process.env.API_AUDIENCE,
    issuerBaseURL: process.env.OIDC_ISSUER_BASE_URL
});

app.use("/passes", jwtCheck);

app.get("/passes/:id", requiredScopes("read:passes"), async (req, res, next) => {
    try {
        const result = await db.query(
            `
                SELECT id, name, document, issued_at, status
                FROM pass
                WHERE id = $1
            `,
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.sendStatus(404);
        }

        const pass = result.rows[0];

        res.json({
            id: pass.id,
            name: pass.name,
            document: pass.document,
            issuedAt: pass.issued_at.toISOString(),
            status: pass.status
        });
    }
    catch (err) {
        next(err);
    }
});

app.post("/passes", requiredScopes("create:passes"), async (req, res, next) => {
    try {
        const { name, document } = req.body;

        if (!name || !name.trim() || !document || !document.trim()) {
            return res.sendStatus(400);
        }

        const id = randomUUID();

        const result = await db.query(
            `
                INSERT INTO pass(id, name, document, status)
                VALUES ($1, $2, $3, 'ACTIVE')
                RETURNING issued_at
            `,
            [id, name.trim(), document.trim()]
        );

        const qr = await QRCode.toBuffer(`${process.env.BASE_URL}/info/${id}`);

        res.status(201).set("Location", `${process.env.BASE_URL}/passes/${id}`).type("image/png").send(qr);
    }
    catch (err) {
        next(err);
    }
});

app.use((err, req, res, next) => {
    console.log(err);
    res.sendStatus(err.statusCode);
});

app.listen(process.env.PORT, "0.0.0.0", () => {
    console.log(`Server listening on port ${process.env.PORT}`);
});