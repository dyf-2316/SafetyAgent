import axios from 'axios';
import type {
  Session,
  Message,
  ToolCall,
  Event,
  EventWithMessages,
  AssetRiskAssessment,
  HardwareInfo,
  PaginatedResponse,
  Statistics,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Sessions API
export const sessionsAPI = {
  list: (params?: { page?: number; page_size?: number }) =>
    api.get<PaginatedResponse<Session>>('/sessions/', { params }),
  
  get: (sessionId: string) =>
    api.get<Session>(`/sessions/${sessionId}`),
  
  getMessages: (sessionId: string, params?: { page?: number; page_size?: number }) =>
    api.get<PaginatedResponse<Message>>(`/sessions/${sessionId}/messages/`, { params }),
  
  getToolCalls: (sessionId: string, params?: { page?: number; page_size?: number }) =>
    api.get<PaginatedResponse<ToolCall>>(`/sessions/${sessionId}/tool-calls/`, { params }),
};

// Messages API
export const messagesAPI = {
  list: (params?: { session_id?: string; role?: string; page?: number; page_size?: number }) =>
    api.get<PaginatedResponse<Message>>('/messages/', { params }),
  
  get: (messageId: string) =>
    api.get<Message>(`/messages/${messageId}`),
};

// Tool Calls API
export const toolCallsAPI = {
  list: (params?: { session_id?: string; tool_name?: string; page?: number; page_size?: number }) =>
    api.get<PaginatedResponse<ToolCall>>('/tool-calls/', { params }),
  
  get: (toolCallId: string) =>
    api.get<ToolCall>(`/tool-calls/${toolCallId}`),
};

// Events API
export const eventsAPI = {
  list: (params?: { session_id?: string; page?: number; page_size?: number }) =>
    api.get<PaginatedResponse<Event>>('/events/', { params }),
  
  get: (eventId: string) =>
    api.get<EventWithMessages>(`/events/${eventId}`),
  
  overview: () =>
    api.get('/events/stats/overview'),
};

// Assets API
export const assetsAPI = {
  assessPath: (path: string) =>
    api.get<AssetRiskAssessment>('/assets/assess-path', { params: { path } }),
  
  hardware: () =>
    api.get<HardwareInfo>('/assets/hardware'),
  
  /** Start an async scan — returns { scan_id, status } */
  startScan: (data: { path?: string; max_depth?: number; scan_system_root?: boolean }) =>
    api.post('/assets/scan', data),

  /** Poll scan progress */
  scanProgress: (scanId: string) =>
    api.get('/assets/scan/progress', { params: { scan_id: scanId } }),

  /** Legacy: kept for backward compat but now prefer startScan + scanProgress */
  scan: (data: { path?: string; max_depth?: number; scan_system_root?: boolean }) =>
    api.post('/assets/scan', data),
  
  overview: () =>
    api.get('/assets/stats/overview'),
};

// Red Team API
export const redteamAPI = {
  listInstructions: () =>
    api.get<{ record_id: string; instruction: string }[]>('/redteam/instructions'),

  generate: (recordId: string) =>
    api.post<{
      record_id: string;
      instruction: string;
      name: string;
      description: string;
      risk_type: string;
      turns: { thought: string; output: string }[];
    }>('/redteam/generate', { record_id: recordId }),

  startSession: () =>
    api.post<{ session_key: string; status: string }>('/redteam/start-session'),

  sendMessage: (sessionKey: string, message: string) =>
    api.post<{
      run_id: string;
      state: string;
      response_text: string;
      usage: Record<string, any> | null;
      stop_reason: string | null;
    }>('/redteam/send-message', { session_key: sessionKey, message }),

  closeSession: (sessionKey: string) =>
    api.post('/redteam/close-session', null, { params: { session_key: sessionKey } }),
};

// Statistics API
export const statsAPI = {
  overview: () =>
    api.get<Statistics>('/stats/overview'),
  
  toolUsage: () =>
    api.get('/stats/tool-usage'),
};

export default api;
