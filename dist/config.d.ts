import type { EvaluationOptions } from "./core/index.ts";
export type MoronMode = "enforce" | "audit" | "off";
export interface LoadedMoronConfig {
    path?: string;
    sources: string[];
    warnings: string[];
    options: EvaluationOptions;
    enabled?: boolean;
    mode: MoronMode;
    failClosed: boolean;
    userBash: boolean;
    maxCommandBytes: number;
}
export declare function loadMoronConfig(cwd: string, env?: NodeJS.ProcessEnv): LoadedMoronConfig;
