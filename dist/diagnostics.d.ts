export declare function commandDigest(command: string): string;
export declare function redactDiagnosticText(value: string, maxLength?: number): string;
export declare function safeDiagnosticCommand(command: string): {
    digest: string;
    preview: string;
};
