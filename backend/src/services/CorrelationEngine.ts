import { NormalizedAlert } from './NormalizationService';

export interface CorrelatedIncident {
  id?: string;
  title: string;
  severity: string;
  riskScore: number;
  confidence: number;
  source?: string;
  target?: string;
  description: string;
  mitreTechniques: string[];
  alerts: NormalizedAlert[];
}

export class CorrelationEngine {
  private activeIncidents: Map<string, CorrelatedIncident> = new Map();
  // Grouping time window in milliseconds (e.g., 5 minutes)
  private TIME_WINDOW = 5 * 60 * 1000;

  /**
   * Processes a new normalized alert and correlates it into existing incidents
   * or creates a new one.
   */
  processAlert(alert: NormalizedAlert): CorrelatedIncident | null {
    // 1. Define the correlation key (e.g., Target IP / Agent)
    // We group attacks targeting the same endpoint.
    const targetKey = alert.targetIp || alert.agentName;

    if (!targetKey) {
      return null; // Cannot correlate without a target
    }

    let incident = this.activeIncidents.get(targetKey);

    if (incident) {
      // Check time window
      const lastAlertTime = incident.alerts[incident.alerts.length - 1].timestamp.getTime();
      const currentAlertTime = alert.timestamp.getTime();

      if (currentAlertTime - lastAlertTime <= this.TIME_WINDOW) {
        // Correlate: add to existing incident
        incident.alerts.push(alert);
        this.updateIncidentMetrics(incident, alert);
        return incident;
      }
    }

    // 2. If no active incident matches, create a new one.
    // We don't instantly create an "incident" for a single LOW alert in production,
    // but for the demo we assume it's the start of a potential chain.
    const newIncident = this.createNewIncident(alert, targetKey);
    this.activeIncidents.set(targetKey, newIncident);

    return newIncident;
  }

  private createNewIncident(alert: NormalizedAlert, targetKey: string): CorrelatedIncident {
    return {
      title: `Suspicious Activity on ${targetKey}`,
      severity: alert.severity,
      riskScore: this.calculateBaseRisk(alert),
      confidence: 50, // Base confidence
      source: alert.sourceIp,
      target: targetKey,
      description: `Detected initial suspicious activity: ${alert.description}`,
      mitreTechniques: alert.mitreTechnique || [],
      alerts: [alert]
    };
  }

  private updateIncidentMetrics(incident: CorrelatedIncident, newAlert: NormalizedAlert) {
    // Add unique MITRE techniques
    if (newAlert.mitreTechnique) {
      newAlert.mitreTechnique.forEach(t => {
        if (!incident.mitreTechniques.includes(t)) {
          incident.mitreTechniques.push(t);
        }
      });
    }

    // Update risk score dynamically based on number of alerts and severity
    let additionalRisk = 0;
    if (newAlert.severity === 'CRITICAL') additionalRisk = 20;
    else if (newAlert.severity === 'HIGH') additionalRisk = 10;
    else if (newAlert.severity === 'MEDIUM') additionalRisk = 5;
    else additionalRisk = 2;

    incident.riskScore = Math.min(100, incident.riskScore + additionalRisk);

    // Confidence grows as more correlated evidence arrives
    incident.confidence = Math.min(99, incident.confidence + 5);

    // Update title/description if escalation occurs
    if (incident.alerts.length > 5 && incident.riskScore > 70) {
      incident.title = `POSSIBLE COMPROMISE: ${incident.target}`;
      incident.description = `Correlated ${incident.alerts.length} events indicating a structured attack involving multiple MITRE techniques.`;
      incident.severity = 'CRITICAL';
    }
  }

  private calculateBaseRisk(alert: NormalizedAlert): number {
    switch (alert.severity) {
      case 'CRITICAL': return 60;
      case 'HIGH': return 40;
      case 'MEDIUM': return 20;
      default: return 10;
    }
  }
}
