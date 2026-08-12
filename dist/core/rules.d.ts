import { type ShellCommand } from "../shell-parser.ts";
import { type EvaluationContext, type RuleFinding } from "./types.ts";
export declare function evaluateCommandRules(command: ShellCommand, context: EvaluationContext): RuleFinding[];
