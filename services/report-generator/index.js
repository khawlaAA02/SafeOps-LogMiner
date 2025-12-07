const express = require("express");
const { Pool } = require("pg");
const dotenv = require("dotenv");
const PDFDocument = require("pdfkit");
const Handlebars = require("handlebars");

dotenv.config();

const app = express();
const port = process.env.PORT || 3006;

// Pool PostgreSQL
const pool = new Pool({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  database: process.env.PG_DB,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
});

// Template HTML (Handlebars)
const htmlTemplate = Handlebars.compile(`
  <html>
    <head>
      <meta charset="utf-8" />
      <title>Security Report #{{id}}</title>
    </head>
    <body>
      <h1>Rapport de sécurité – Pipeline: {{pipeline_name}}</h1>
      <p><b>Statut global :</b> {{overall_status}}</p>
      <p><b>Généré le :</b> {{created_at}}</p>

      <h2>Vulnérabilités</h2>
      <ul>
        {{#each vulnerabilities}}
          <li>{{this.type}} – {{this.detail}}</li>
        {{/each}}
      </ul>

      <h2>Suggestions</h2>
      <ul>
        {{#each suggestions}}
          <li>{{this.text}}</li>
        {{/each}}
      </ul>

      <h2>Anomalies</h2>
      <ul>
        {{#each anomalies}}
          <li>Score: {{this.score}} – Label: {{this.label}}</li>
        {{/each}}
      </ul>
    </body>
  </html>
`);

// Route de test
app.get("/", (req, res) => {
  res.json({ message: "ReportGenerator is running" });
});

// GET /report/:id?format=html|pdf|sarif
app.get("/report/:id", async (req, res) => {
  const id = req.params.id;
  const format = (req.query.format || "html").toLowerCase();

  try {
    const result = await pool.query(
      "SELECT * FROM security_reports WHERE id = $1",
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Report not found" });
    }

    const row = result.rows[0];

    // S'assurer que les champs JSON sont des tableaux
    const report = {
      id: row.id,
      pipeline_name: row.pipeline_name,
      overall_status: row.overall_status,
      vulnerabilities: row.vulnerabilities || [],
      suggestions: row.suggestions || [],
      anomalies: row.anomalies || [],
      created_at: row.created_at,
    };

    if (format === "pdf") {
      // 👉 Génération PDF
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `inline; filename="security-report-${id}.pdf"`
      );

      const doc = new PDFDocument();
      doc.pipe(res);

      doc.fontSize(20).text(`Rapport de sécurité #${id}`, { underline: true });
      doc.moveDown();
      doc.fontSize(14).text(`Pipeline : ${report.pipeline_name}`);
      doc.text(`Statut global : ${report.overall_status}`);
      doc.text(`Généré le : ${report.created_at}`);
      doc.moveDown();

      doc.fontSize(16).text("Vulnérabilités :", { underline: true });
      doc.fontSize(12);
      report.vulnerabilities.forEach((v) => {
        doc.text(`- ${v.type} : ${v.detail}`);
      });
      doc.moveDown();

      doc.fontSize(16).text("Suggestions :", { underline: true });
      doc.fontSize(12);
      report.suggestions.forEach((s) => {
        doc.text(`- ${s.text}`);
      });
      doc.moveDown();

      doc.fontSize(16).text("Anomalies :", { underline: true });
      doc.fontSize(12);
      report.anomalies.forEach((a) => {
        doc.text(`- score=${a.score} label=${a.label}`);
      });

      doc.end();
      return;
    }

    if (format === "sarif") {
      // 👉 Export SARIF très simplifié
      const sarif = {
        version: "2.1.0",
        runs: [
          {
            tool: {
              driver: {
                name: "SafeOps-LogMiner",
                informationUri: "https://example.com/safeops",
              },
            },
            results: report.vulnerabilities.map((v) => ({
              ruleId: v.type,
              level: "error",
              message: { text: v.detail },
            })),
          },
        ],
      };

      return res.json(sarif);
    }

    // 👉 HTML (par défaut)
    const html = htmlTemplate(report);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(html);
  } catch (err) {
    console.error("Error in /report/:id", err);
    return res.status(500).json({ error: "Error while generating report" });
  }
});

// Démarrer le serveur
app.listen(port, () => {
  console.log(`ReportGenerator running on port ${port}`);
});
