import type { ChatMessage, ApiSpec } from './assistant';
import type { SecurityFindingInput, AnalysisResponse } from './security';

export type WorkspaceView =
  | 'chat'
  | 'cowork'
  | 'dashboard'
  | 'inventory'
  | 'findings'
  | 'reports'
  | 'settings';

export interface ChatSession {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messages: ChatMessage[];
  specId?: string;
  isArchived?: boolean;
}

export type StepStatus = 'pending' | 'running' | 'completed' | 'failed' | 'waiting_approval';

export interface CoworkStep {
  id: string;
  name: string;
  description: string;
  status: StepStatus;
  output?: string;
  timestamp?: string;
}

export interface CoworkTask {
  id: string;
  title: string;
  description: string;
  category: 'audit' | 'bola' | 'mass_assignment' | 'report';
  status: 'idle' | 'running' | 'waiting_approval' | 'completed' | 'failed';
  progress: number; // 0 - 100
  currentStepIndex: number;
  steps: CoworkStep[];
  findingInput?: SecurityFindingInput;
  analysisResult?: AnalysisResponse;
  reportMarkdown?: string;
  createdAt: number;
}
