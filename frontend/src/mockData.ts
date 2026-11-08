export const mockIncidents = [
  {
    id: "INC-001",
    title: "POSSIBLE CREDENTIAL COMPROMISE",
    severity: "CRITICAL",
    riskScore: 91,
    confidence: 94,
    status: "INVESTIGATING",
    source: "192.168.252.11 (Kali)",
    target: "192.168.252.9 (Ubuntu)",
    affectedEndpoints: 4,
    timestamp: "2026-08-31T10:32:20Z",
    description: "Multiple failed authentication events followed by successful login, suspicious process execution, and privileged activity.",
    alertsCount: 37,
    mitreTechniques: ["T1110", "T1078", "T1059"]
  },
  {
    id: "INC-002",
    title: "LATERAL MOVEMENT SUSPECTED",
    severity: "HIGH",
    riskScore: 78,
    confidence: 82,
    status: "NEW",
    source: "192.168.252.9",
    target: "Internal Network",
    affectedEndpoints: 2,
    timestamp: "2026-08-31T09:15:00Z",
    description: "Anomalous SMB traffic and remote service execution detected following irregular login hours.",
    alertsCount: 14,
    mitreTechniques: ["T1021", "T1569"]
  }
];

export const mockAiAnalysis = {
  "INC-001": {
    whatHappened: "37 authentication failures were detected from a single source within 45 seconds. A successful authentication followed the failed attempts. The endpoint subsequently generated suspicious process activity.",
    whySuspicious: "This sequence is consistent with a possible credential brute-force attack followed by unauthorized access.",
    confidence: 94,
    risk: 91,
    recommendedInvestigation: [
      "Review successful authentication",
      "Investigate source IP",
      "Review process tree",
      "Check privilege activity",
      "Inspect other endpoints contacted by the account"
    ],
    blastRadius: {
      level: "HIGH",
      endpoints: 7,
      users: 4,
      servers: 2,
      privilegedAccounts: 3
    },
    prediction: [
      { stage: "Lateral Movement", probability: 82 },
      { stage: "Data Discovery", probability: 67 },
      { stage: "Exfiltration", probability: 51 },
      { stage: "Ransomware Deployment", probability: 38 }
    ],
    predictedTarget: "Finance-Server-02"
  }
};

export const mockTimeline = {
  "INC-001": [
    { id: 1, time: "14:32:01", event: "Failed SSH login", severity: "Low", detail: "Invalid password for user root" },
    { id: 2, time: "14:32:03", event: "Failed SSH login", severity: "Low", detail: "Invalid password for user root" },
    { id: 3, time: "14:32:08", event: "Authentication threshold exceeded", severity: "Medium", detail: "15 failed logins within 60s" },
    { id: 4, time: "14:32:10", event: "Successful authentication", severity: "High", detail: "Login successful from suspicious IP" },
    { id: 5, time: "14:32:15", event: "Suspicious process execution", severity: "Critical", detail: "Execution of encoded bash script" },
    { id: 6, time: "14:32:18", event: "Privilege-related activity", severity: "Critical", detail: "Sudo command executed without tty" },
    { id: 7, time: "14:32:20", event: "INCIDENT CREATED", severity: "Info", detail: "Correlation engine grouped 37 alerts" }
  ]
};

export const mockGraphData = {
  "INC-001": {
    nodes: [
      { id: 'ip-1', data: { label: 'Suspicious IP\n192.168.252.11' }, position: { x: 250, y: 0 }, type: 'input' },
      { id: 'ep-1', data: { label: 'Kali Endpoint' }, position: { x: 250, y: 100 } },
      { id: 'user-1', data: { label: 'User Login' }, position: { x: 100, y: 200 } },
      { id: 'proc-1', data: { label: 'Process\n(bash -c)' }, position: { x: 250, y: 200 } },
      { id: 'net-1', data: { label: 'Network' }, position: { x: 400, y: 200 } },
      { id: 'priv-1', data: { label: 'Privilege Activity' }, position: { x: 250, y: 300 } },
      { id: 'target-1', data: { label: 'Target Server\nUbuntu VM' }, position: { x: 250, y: 400 } },
      { id: 'data-1', data: { label: 'Sensitive Data' }, position: { x: 250, y: 500 }, type: 'output' },
    ],
    edges: [
      { id: 'e1', source: 'ip-1', target: 'ep-1', label: 'ORIGINATES' },
      { id: 'e2', source: 'ep-1', target: 'user-1', label: 'AUTHENTICATES' },
      { id: 'e3', source: 'ep-1', target: 'proc-1', label: 'EXECUTES' },
      { id: 'e4', source: 'ep-1', target: 'net-1', label: 'CONNECTS' },
      { id: 'e5', source: 'proc-1', target: 'priv-1', label: 'ESCALATES' },
      { id: 'e6', source: 'priv-1', target: 'target-1', label: 'ACCESSES' },
      { id: 'e7', source: 'target-1', target: 'data-1', label: 'EXFILTRATES' },
    ]
  }
};
