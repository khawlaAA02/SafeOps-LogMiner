const crypto = require("crypto");
const axios = require("axios");
const unzipper = require("unzipper");

function verifyGitHubSignature(req, safeEqual) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  const sig = req.header("x-hub-signature-256") || "";
  if (!secret || !sig.startsWith("sha256=")) return false;

  const expected =
    "sha256=" + crypto.createHmac("sha256", secret).update(req.body).digest("hex");

  return safeEqual(sig, expected);
}

async function fetchGitHubRunLogs({ owner, repo, runId }) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) throw new Error("GITHUB_TOKEN missing");

  const url = `https://api.github.com/repos/${owner}/${repo}/actions/runs/${runId}/logs`;

  const resp = await axios.get(url, {
    responseType: "arraybuffer",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "safeops-logcollector",
    },
  });

  const directory = await unzipper.Open.buffer(Buffer.from(resp.data));
  const parts = [];
  for (const f of directory.files) {
    if (f.type !== "File") continue;
    const content = (await f.buffer()).toString("utf8");
    parts.push(`===== ${f.path} =====\n${content}`);
  }
  return parts.join("\n\n");
}

/**
 * Build a standard ingestion doc from GitHub webhook payload
 * We focus on workflow_run completed events.
 */
async function buildDocFromGithubWebhook({ event, payload }) {
  if (event !== "workflow_run" || payload?.action !== "completed") return null;

  const repoFull = payload?.repository?.full_name; // owner/repo
  const runId = payload?.workflow_run?.id;
  const conclusion = payload?.workflow_run?.conclusion || "unknown";

  const [owner, repo] = String(repoFull || "/").split("/");
  if (!owner || !repo || !runId) throw new Error("Missing owner/repo/runId");

  const raw = await fetchGitHubRunLogs({ owner, repo, runId });

  return {
    source: "github",
    pipelineId: payload?.workflow_run?.name || "github-actions",
    runId: String(runId),
    repo: repoFull,
    branch: payload?.workflow_run?.head_branch || null,
    status: conclusion,
    raw,
    meta: {
      provider: "github",
      owner,
      repo,
      run_id: runId,
      html_url: payload?.workflow_run?.html_url,
      created_at: payload?.workflow_run?.created_at,
      updated_at: payload?.workflow_run?.updated_at,
      job_id: "workflow_run",
    },
    ingestType: "webhook",
    step: "github-actions",
    level: conclusion === "success" ? "info" : "error",
  };
}

module.exports = { verifyGitHubSignature, buildDocFromGithubWebhook };
