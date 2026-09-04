'use strict';

const devRepos = new Map();
const devScans = new Map();
const devFindings = new Map();

module.exports = {
  devRepos,
  devScans,
  devFindings,

  saveRepo(repo) {
    devRepos.set(repo.id, repo);
    return repo;
  },

  getRepo(id) {
    return devRepos.get(id);
  },

  saveScan(scan) {
    devScans.set(scan.id, scan);
    return scan;
  },

  getScan(id) {
    return devScans.get(id);
  },

  saveFindings(scanId, findings) {
    devFindings.set(scanId, findings);
    return findings;
  },

  getFindings(scanId) {
    return devFindings.get(scanId) || [];
  }
};
