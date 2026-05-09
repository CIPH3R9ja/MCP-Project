import type { IntentAnalysis, NonHumanIdentity, ToolEvent } from "./types.js";
export declare function detectNHIs(event: ToolEvent): NonHumanIdentity[];
export declare function analyzeIntent(event: ToolEvent): Promise<IntentAnalysis>;
export declare function queueIntentAnalysis(event: ToolEvent): Promise<IntentAnalysis>;
//# sourceMappingURL=analyzer.d.ts.map