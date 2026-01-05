const axios = require("axios");

async function fetchGitLabJobTrace({ projectId, jobId }) {
  const token = process.env.GITLAB_TOKEN;
  const base = process.env.GITLAB_BASE_URL || "https://gitlab.com";
  if (!token) throw new Error("GITLAB_TOKEN missing");

  const url = `${base}/api/v4/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}/trace`;
  const resp = await axios.get(url, { headers: { "PRIVATE-TOKEN": token } });
  return String(resp.data || "");
}

/**
 * body: { projectId, jobId, pipelineId?, status?, ref?, repo? }
 */
async function buildDocFromGitlabFetch(body) {
  const { projectId, jobId, pipelineId, status, ref, repo } = body || {};
  if (!projectId || !jobId) throw new Error("projectId and jobId required");

  const raw = await fetchGitLabJobTrace({ projectId, jobId });

  return {
    source: "gitlab",
    pipelineId: pipelineId || "gitlab-ci",
    runId: String(jobId),
    repo: repo || String(projectId),
    branch: ref || null,
    status: status || "unknown",
    raw,
    meta: { provider: "gitlab", projectId, jobId, ref, job_id: String(jobId) },
    ingestType: "pull",
    step: "gitlab-ci",
    level: "info",
  };
}

module.exports = { buildDocFromGitlabFetch };
