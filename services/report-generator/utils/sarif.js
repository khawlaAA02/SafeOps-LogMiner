module.exports.toSarif = function (findings) {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SafeOps-LogMiner",
            rules: findings.map(f => ({
              id: f.rule_id,
              name: f.title,
              shortDescription: { text: f.description }
            }))
          }
        },
        results: findings.map(f => ({
          ruleId: f.rule_id,
          level: f.severity,
          message: { text: f.description }
        }))
      }
    ]
  };
};
