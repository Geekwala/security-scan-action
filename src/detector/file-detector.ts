/**
 * Dependency file detection logic
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { isFileSupported, getFilePriority, getSupportedFileNames } from './file-patterns';

export class FileNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FileNotFoundError';
  }
}

/**
 * Detect dependency file in the repository
 * Searches in priority order (lockfiles before manifests)
 */
export async function detectDependencyFile(workspaceDir = '.'): Promise<string> {
  const supportedFiles = getSupportedFileNames().filter(name => !name.includes('*'));

  const foundFiles: Array<{ path: string; priority: number }> = [];

  for (const fileName of supportedFiles) {
    const filePath = path.join(workspaceDir, fileName);

    try {
      await fs.access(filePath, fs.constants.R_OK);
      foundFiles.push({
        path: filePath,
        priority: getFilePriority(fileName),
      });
    } catch {
      // File doesn't exist or not readable, continue
      continue;
    }
  }

  // Check for .csproj files
  try {
    const files = await fs.readdir(workspaceDir);
    for (const file of files) {
      if (file.endsWith('.csproj')) {
        const filePath = path.join(workspaceDir, file);
        foundFiles.push({
          path: filePath,
          priority: getFilePriority(file),
        });
      }
    }
  } catch {
    // Directory read error, ignore
  }

  if (foundFiles.length === 0) {
    throw new FileNotFoundError(
      `No supported dependency files found in ${workspaceDir}. ` +
        `Supported files: ${getSupportedFileNames().join(', ')}`
    );
  }

  // Sort by priority and return the highest priority file
  foundFiles.sort((a, b) => a.priority - b.priority);
  return foundFiles[0].path;
}

/**
 * Validate that a file exists and is supported
 */
export async function validateFile(filePath: string): Promise<void> {
  const fileName = path.basename(filePath);

  if (!isFileSupported(fileName)) {
    throw new FileNotFoundError(
      `Unsupported file: ${fileName}. Supported files: ${getSupportedFileNames().join(', ')}`
    );
  }

  try {
    await fs.access(filePath, fs.constants.R_OK);
  } catch {
    throw new FileNotFoundError(`File not found or not readable: ${filePath}`);
  }
}

/**
 * Read file content
 */
export async function readFile(filePath: string): Promise<string> {
  try {
    return await fs.readFile(filePath, 'utf-8');
  } catch (error) {
    throw new FileNotFoundError(
      `Failed to read file ${filePath}: ${(error as Error).message}`
    );
  }
}
