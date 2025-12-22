module.exports.computeScore = function (vulns, anomalies) {
  let score = 100;

  for (const v of vulns) {
    if (v.severity === "critical") score -= 30;
    else if (v.severity === "high") score -= 20;
    else if (v.severity === "medium") score -= 10;
    else score -= 5;
  }

  score -= anomalies * 5;
  return Math.max(score, 0);
};
