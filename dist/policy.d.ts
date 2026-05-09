import type { Alert, ToolEvent } from "./types.js";
type AlertCallback = (alert: Alert) => void;
export declare function onAlert(cb: AlertCallback): void;
export declare function evaluateEvent(event: ToolEvent): {
    blocked: boolean;
    alerts: Alert[];
    flag_reason?: string;
};
export {};
//# sourceMappingURL=policy.d.ts.map