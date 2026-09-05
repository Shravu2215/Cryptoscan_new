/**
 * System / Application-Level Risk Rollup Service.
 *
 * Groups cryptographic findings by top-level directory / service module
 * and computes system-level posture metrics.
 */

'use strict';

function getSystemName(filePath) {
  if (!filePath || typeof filePath !== 'string') return 'Root Application';
  const cleanPath = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const parts = cleanPath.split('/');
  
  if (parts.length > 1) {
    const topDir = parts[0].toLowerCase();
    if (['src', 'lib', 'app', 'pkg', 'internal'].includes(topDir) && parts.length > 2) {
      return `${parts[0]}/${parts[1]}`;
    }
    return parts[0];
  }
  return 'Core Repository';
}

function rollupSystems(findings = []) {
  const systems = {};

  findings.forEach(f => {
    const sysName = getSystemName(f.file || f.filePath);
    if (!systems[sysName]) {
      systems[sysName] = {
        name: sysName,
        totalFindings: 0,
        quantumVulnerableCount: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        highestSeverity: 'LOW',
        riskScores: [],
      };
    }

    const sys = systems[sysName];
    sys.totalFindings += 1;

    const sev = (f.severity || (f.vulnerability && f.vulnerability.severity) || 'LOW').toUpperCase();
    if (sev === 'CRITICAL') sys.criticalCount++;
    else if (sev === 'HIGH') sys.highCount++;
    else if (sev === 'MEDIUM') sys.mediumCount++;
    else sys.lowCount++;

    const isQuant = f.quantum === 'yes' || (f.quantumStatus || '').toLowerCase().includes('vulnerable') || (f.pqcMigration && f.pqcMigration.quantumExposure > 0);
    if (isQuant) sys.quantumVulnerableCount++;

    const score = f.vulnerability ? f.vulnerability.finalRiskScore : (sev === 'CRITICAL' ? 90 : (sev === 'HIGH' ? 70 : (sev === 'MEDIUM' ? 40 : 20)));
    sys.riskScores.push(score);
  });

  const result = Object.values(systems).map(sys => {
    let highestSeverity = 'SAFE';
    if (sys.criticalCount > 0) highestSeverity = 'CRITICAL';
    else if (sys.highCount > 0) highestSeverity = 'HIGH';
    else if (sys.mediumCount > 0) highestSeverity = 'MEDIUM';
    else if (sys.lowCount > 0) highestSeverity = 'LOW';

    const avgScore = sys.riskScores.length > 0 ? Math.round(sys.riskScores.reduce((a, b) => a + b, 0) / sys.riskScores.length) : 0;

    return {
      name: sys.name,
      totalFindings: sys.totalFindings,
      quantumVulnerableCount: sys.quantumVulnerableCount,
      highestSeverity,
      overallScore: avgScore,
      breakdown: {
        critical: sys.criticalCount,
        high: sys.highCount,
        medium: sys.mediumCount,
        low: sys.lowCount
      }
    };
  });

  result.sort((a, b) => b.overallScore - a.overallScore);
  return result;
}

module.exports = {
  getSystemName,
  rollupSystems
};
