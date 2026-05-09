import type { ToolEvent, Session, Alert, AlertRule, MonitorStats } from "./types.js";
export declare function initDb(): void;
export declare function insertEvent(event: ToolEvent): void;
export declare function getEvents(opts: {
    limit?: number;
    offset?: number;
    session_id?: string;
    tool_name?: string;
    flagged?: boolean;
    since?: number;
}): ToolEvent[];
export declare function getEvent(id: string): ToolEvent | null;
export declare function upsertSession(data: Partial<Session> & {
    id: string;
}): void;
export declare function getSessions(limit?: number): Session[];
export declare function insertAlert(alert: Alert): void;
export declare function getAlerts(limit?: number): Alert[];
export declare function getAlertRules(): AlertRule[];
export declare function updateAlertRule(id: string, update: Partial<AlertRule>): void;
export declare function getStats(): MonitorStats;
export declare function exportEvents(format: "json" | "csv", since?: number): string;
//# sourceMappingURL=db.d.ts.map