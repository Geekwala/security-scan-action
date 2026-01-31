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
//# sourceMappingURL=input-validator.d.ts.map