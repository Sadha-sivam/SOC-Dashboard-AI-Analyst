export interface AIAnalysisRequest {
  incidentId: string;
  alerts: any[];
  graphData: any;
}

export interface AIAnalysisResponse {
  whatHappened: string;
  whySuspicious: string;
  confidence: number;
  risk: number;
  recommendedInvestigation: string[];
  blastRadius: {
    level: string;
    endpoints: number;
    users: number;
    servers: number;
    privilegedAccounts: number;
  };
  prediction: {
    stage: string;
    probability: number;
  }[];
  predictedTarget?: string;
}

export interface AIProvider {
  analyzeIncident(request: AIAnalysisRequest): Promise<AIAnalysisResponse>;
}

export class AIAnalystService {
  private provider: AIProvider;

  constructor(provider: AIProvider) {
    this.provider = provider;
  }

  async runAnalysis(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
    return this.provider.analyzeIncident(request);
  }
}
