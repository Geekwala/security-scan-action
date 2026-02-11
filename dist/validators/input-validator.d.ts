/**
 * Input validation for GitHub Action inputs
 */
import { ActionInputs } from '../api/types';
export declare class InputValidationError extends Error {
    constructor(message: string);
}
/**
 * Parse and validate GitHub Action inputs
 */
export declare function validateInputs(): ActionInputs;
/**
 * Validate that a file path stays within the workspace directory (defense-in-depth against path traversal)
 */
export declare function validateFilePath(filePath: string, inputName: string): string;
//# sourceMappingURL=input-validator.d.ts.map