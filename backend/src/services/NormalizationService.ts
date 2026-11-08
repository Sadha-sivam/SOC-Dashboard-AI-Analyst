export interface NormalizedAlert {
  wazuhId: string;
  severity: string;
  timestamp: Date;
  ruleId: string;
  description: string;

  sourceIp?: string;
  targetIp?: string;
  mitreTechnique?: string[];

  agentId: string;
  agentName: string;

  // Windows event metadata
  eventId?: string;
  channel?: string;
  computer?: string;
  user?: string;
  logonType?: string;
  logonId?: string;

  // Process evidence
  processName?: string;
  processPath?: string;
  processId?: string;
  processGuid?: string;
  parentProcessName?: string;
  parentProcessPath?: string;
  parentProcessId?: string;
  parentProcessGuid?: string;
  commandLine?: string;

  // File evidence
  filePath?: string;
  fileHashes?: string;

  rawEvent: any;
}

function firstValue(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (value === undefined || value === null || value === '') continue;

    const result = String(value).trim();
    if (result && result !== '-') return result;
  }

  return undefined;
}

function stringArray(value: unknown): string[] {
  if (value === undefined || value === null) return [];

  return (Array.isArray(value) ? value : [value])
    .map((item) => String(item).trim())
    .filter(Boolean);
}

function validTimestamp(value: unknown): Date {
  const date = new Date(
    typeof value === 'string' || typeof value === 'number'
      ? value
      : Date.now(),
  );

  return Number.isNaN(date.getTime()) ? new Date() : date;
}

export class NormalizationService {
  normalize(rawAlert: any): NormalizedAlert {
    const data = rawAlert?.data ?? {};
    const win = data?.win?.eventdata ?? {};
    const sys = data?.win?.system ?? {};
    const process = data?.process ?? {};
    const file = data?.file ?? {};
    const rule = rawAlert?.rule ?? {};
    const agent = rawAlert?.agent ?? {};

    const mitreTechnique = stringArray(rule?.mitre?.id);

    const level = Number(rule?.level ?? 0);

    let severity = 'LOW';
    if (level >= 12) severity = 'CRITICAL';
    else if (level >= 8) severity = 'HIGH';
    else if (level >= 5) severity = 'MEDIUM';

    return {
      wazuhId: firstValue(rawAlert?.id) ??
        `wazuh-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,

      severity,
      timestamp: validTimestamp(
        rawAlert?.['@timestamp'] ?? rawAlert?.timestamp,
      ),

      ruleId: firstValue(rule?.id) ?? 'unknown',
      description: firstValue(rule?.description) ?? 'Unknown event',

      sourceIp: firstValue(
        data?.srcip,
        data?.src_ip,
        data?.source?.ip,
        win?.sourceIp,
        win?.ipAddress,
      ),

      targetIp: firstValue(
        agent?.ip,
        data?.destip,
        data?.dstip,
        data?.destination?.ip,
        win?.destinationIp,
      ),

      mitreTechnique,
      agentId: firstValue(agent?.id) ?? 'unknown',
      agentName: firstValue(agent?.name) ?? 'unknown',

      eventId: firstValue(sys?.eventID, sys?.eventId),
      channel: firstValue(sys?.channel),
      computer: firstValue(sys?.computer, win?.workstationName),

      user: firstValue(
        win?.targetUserName,
        win?.subjectUserName,
        win?.user,
        data?.dstuser,
        data?.srcuser,
        data?.user,
      ),

      logonType: firstValue(win?.logonType),
      logonId: firstValue(win?.targetLogonId, win?.subjectLogonId, win?.logonId),

      processName: firstValue(
        win?.processName,
        win?.image,
        win?.newProcessName,
        process?.name,
      ),

      processPath: firstValue(
        win?.image,
        win?.processName,
        process?.executable,
      ),

      processId: firstValue(
        win?.processId,
        process?.pid,
      ),

      processGuid: firstValue(
        win?.processGuid,
        process?.guid,
      ),

      parentProcessName: firstValue(
        win?.parentImage,
        win?.parentProcessName,
        process?.parent?.name,
      ),

      parentProcessPath: firstValue(
        win?.parentImage,
        process?.parent?.executable,
      ),

      parentProcessId: firstValue(
        win?.parentProcessId,
        process?.parent?.pid,
      ),

      parentProcessGuid: firstValue(
        win?.parentProcessGuid,
        process?.parent?.guid,
      ),

      commandLine: firstValue(
        win?.commandLine,
        process?.command_line,
      ),

      filePath: firstValue(
        win?.targetFilename,
        file?.path,
        rawAlert?.syscheck?.path,
      ),

      fileHashes: firstValue(
        win?.hashes,
        file?.hash?.sha256,
        file?.hash,
        rawAlert?.syscheck?.sha256_after,
      ),

      rawEvent: rawAlert,
    };
  }
}
