const axios = require("axios");

async function fetchJenkinsConsole({ job, buildNumber }) {
  const base = process.env.JENKINS_BASE_URL;
  const user = process.env.JENKINS_USER;
  const token = process.env.JENKINS_API_TOKEN;
  if (!base || !user || !token) throw new Error("JENKINS_* env missing");

  const url = `${base}/job/${encodeURIComponent(job)}/${encodeURIComponent(buildNumber)}/consoleText`;
  const resp = await axios.get(url, { auth: { username: user, password: token } });
  return String(resp.data || "");
}

/**
 * body: { job, buildNumber, pipelineId?, status? }
 */
async function buildDocFromJenkinsFetch(body) {
  const { job, buildNumber, pipelineId, status } = body || {};
  if (!job || !buildNumber) throw new Error("job and buildNumber required");

  const raw = await fetchJenkinsConsole({ job, buildNumber });

  return {
    source: "jenkins",
    pipelineId: pipelineId || "jenkins",
    runId: `${job}#${buildNumber}`,
    status: status || "unknown",
    raw,
    meta: { provider: "jenkins", job, buildNumber, job_id: String(job) },
    ingestType: "pull",
    step: "jenkins",
    level: "info",
  };
}

module.exports = { buildDocFromJenkinsFetch };
