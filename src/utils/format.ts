/**
 * Formatting utilities
 */

/**
 * Pluralize "vulnerability" / "vulnerabilities"
 */
export function pluralizeVulnerabilities(count: number): string {
  return `vulnerabilit${count === 1 ? 'y' : 'ies'}`;
}
