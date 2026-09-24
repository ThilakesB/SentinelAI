// Mock data: simulates real-time process telemetry from the CyberGuard agent

export const DEVICES = [
  { id: "dev-1", hostname: "prod-server-01", ip: "192.168.1.100", os: "Ubuntu 22.04", status: "active", threat: "malicious" },
  { id: "dev-2", hostname: "prod-server-02", ip: "192.168.1.101", os: "Ubuntu 22.04", status: "active", threat: "suspicious" },
  { id: "dev-3", hostname: "db-primary-01",  ip: "192.168.1.110", os: "Debian 11",    status: "active", threat: "safe" },
  { id: "dev-4", hostname: "staging-01",     ip: "192.168.1.200", os: "Windows Server 2019", status: "active", threat: "safe" },
  { id: "dev-5", hostname: "backup-node",    ip: "192.168.1.250", os: "Ubuntu 20.04", status: "disconnected", threat: "safe" },
];

let _pid = 1000;
const pid = () => ++_pid;

export const INITIAL_PROCESSES = [
  {
    pid: 1,        name: "systemd",           cpu: 0.1,  ram: 8,     netSent: 0,       netRecv: 0,       ports: 0,  score: 0.01, classification: "SAFE",        exe: "/sbin/init",               signed: true,  parentPid: 0,   childCount: 112 },
  { pid: 452,      name: "sshd",              cpu: 0.2,  ram: 12,    netSent: 42,      netRecv: 38,      ports: 1,  score: 0.04, classification: "SAFE",        exe: "/usr/sbin/sshd",           signed: true,  parentPid: 1,   childCount: 2 },
  { pid: 801,      name: "nginx",             cpu: 0.8,  ram: 48,    netSent: 2100,    netRecv: 890,     ports: 2,  score: 0.06, classification: "SAFE",        exe: "/usr/sbin/nginx",          signed: true,  parentPid: 1,   childCount: 4 },
  { pid: 934,      name: "postgres",          cpu: 3.2,  ram: 812,   netSent: 440,     netRecv: 220,     ports: 1,  score: 0.07, classification: "SAFE",        exe: "/usr/lib/postgresql/14/bin/postgres", signed: true, parentPid: 1, childCount: 9 },
  { pid: 1102,     name: "python3",           cpu: 1.1,  ram: 95,    netSent: 120,     netRecv: 88,      ports: 0,  score: 0.12, classification: "SAFE",        exe: "/usr/bin/python3",         signed: true,  parentPid: 1,   childCount: 0 },
  { pid: 1204,     name: "rsync",             cpu: 2.4,  ram: 36,    netSent: 88400,   netRecv: 1200,    ports: 0,  score: 0.18, classification: "SAFE",        exe: "/usr/bin/rsync",           signed: true,  parentPid: 1,   childCount: 0 },
  { pid: 1389,     name: "journald",          cpu: 0.3,  ram: 22,    netSent: 0,       netRecv: 0,       ports: 0,  score: 0.02, classification: "SAFE",        exe: "/lib/systemd/systemd-journald", signed: true, parentPid: 1, childCount: 0 },
  { pid: 2011,     name: "cron",              cpu: 0.0,  ram: 4,     netSent: 0,       netRecv: 0,       ports: 0,  score: 0.03, classification: "SAFE",        exe: "/usr/sbin/cron",           signed: true,  parentPid: 1,   childCount: 1 },
  { pid: 2234,     name: "node",              cpu: 12.4, ram: 228,   netSent: 4400,    netRecv: 2800,    ports: 3,  score: 0.22, classification: "SAFE",        exe: "/usr/bin/node",            signed: true,  parentPid: 801, childCount: 0 },
  { pid: 3001,     name: "curl",              cpu: 0.4,  ram: 6,     netSent: 880,     netRecv: 12000,   ports: 0,  score: 0.28, classification: "SAFE",        exe: "/usr/bin/curl",            signed: true,  parentPid: 1,   childCount: 0 },
  { pid: 3412,     name: "kworker/2:1",       cpu: 0.1,  ram: 0,     netSent: 0,       netRecv: 0,       ports: 0,  score: 0.01, classification: "SAFE",        exe: "[kworker/2:1]",            signed: true,  parentPid: 2,   childCount: 0 },
  { pid: 4001,     name: "bash",              cpu: 22.1, ram: 14,    netSent: 200,     netRecv: 100,     ports: 0,  score: 0.34, classification: "SUSPICIOUS",  exe: "/bin/bash",                signed: true,  parentPid: 452, childCount: 1 },
  { pid: 4218,     name: "wget",              cpu: 8.4,  ram: 18,    netSent: 4400,    netRecv: 184000,  ports: 0,  score: 0.41, classification: "SUSPICIOUS",  exe: "/usr/bin/wget",            signed: true,  parentPid: 4001,childCount: 0 },
  { pid: 4521,     name: "suspicious_tool",   cpu: 87.4, ram: 2048,  netSent: 1048576, netRecv: 512,     ports: 3,  score: 0.92, classification: "MALICIOUS",   exe: "/tmp/.hidden/suspicious_tool", signed: false, parentPid: 1, childCount: 0 },
  { pid: 4788,     name: "xm64",             cpu: 94.2, ram: 1400,  netSent: 22000,   netRecv: 800,     ports: 1,  score: 0.88, classification: "MALICIOUS",   exe: "/var/tmp/.x/xm64",        signed: false, parentPid: 1,   childCount: 2 },
  { pid: 4801,     name: "python3",           cpu: 44.1, ram: 320,   netSent: 320000,  netRecv: 1100,    ports: 2,  score: 0.76, classification: "MALICIOUS",   exe: "/tmp/pyinstaller/.pkg/a.out", signed: false, parentPid: 4001, childCount: 0 },
  { pid: 5100,     name: "systemd-resolved",  cpu: 0.1,  ram: 16,    netSent: 120,     netRecv: 300,     ports: 1,  score: 0.03, classification: "SAFE",        exe: "/lib/systemd/systemd-resolved", signed: true, parentPid: 1, childCount: 0 },
  { pid: 5230,     name: "auditd",            cpu: 0.5,  ram: 20,    netSent: 0,       netRecv: 0,       ports: 0,  score: 0.05, classification: "SAFE",        exe: "/sbin/auditd",             signed: true,  parentPid: 1,   childCount: 0 },
  { pid: 5400,     name: "containerd",        cpu: 1.8,  ram: 88,    netSent: 1200,    netRecv: 800,     ports: 1,  score: 0.09, classification: "SAFE",        exe: "/usr/bin/containerd",      signed: true,  parentPid: 1,   childCount: 3 },
  { pid: 5601,     name: "dockerd",           cpu: 2.1,  ram: 144,   netSent: 3400,    netRecv: 1800,    ports: 2,  score: 0.11, classification: "SAFE",        exe: "/usr/bin/dockerd",         signed: true,  parentPid: 1,   childCount: 8 },
];

export const WHITELIST_RULES = [
  { id: "wl-1", ruleType: "process_name", ruleValue: "postgres", scope: "global", addedBy: "admin" },
  { id: "wl-2", ruleType: "process_name", ruleValue: "nginx",    scope: "global", addedBy: "admin" },
  { id: "wl-3", ruleType: "process_name", ruleValue: "sshd",     scope: "global", addedBy: "admin" },
];

export function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB/s`;
}

export function formatRam(mb) {
  if (mb < 1024) return `${mb.toFixed(0)} MB`;
  return `${(mb / 1024).toFixed(1)} GB`;
}

// Simulate live process telemetry drift
export function tickProcesses(processes) {
  return processes.map(p => {
    if (p.classification === "WHITELISTED" || p.classification === "KILLED") return p;
    const drift = (v, max, volatility = 0.05) => {
      const d = v + (Math.random() - 0.5) * max * volatility;
      return Math.max(0, Math.min(max, d));
    };
    return {
      ...p,
      cpu: drift(p.cpu, 100, p.classification === "MALICIOUS" ? 0.03 : 0.1),
      ram: drift(p.ram, p.classification === "MALICIOUS" ? 4096 : 1024, 0.02),
      netSent: drift(p.netSent, p.classification === "MALICIOUS" ? 2097152 : 102400, 0.08),
    };
  });
}
