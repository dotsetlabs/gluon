/**
 * Formats output with colors for better readability
 */
export const colors = {
    green: (text: string) => `\x1b[32m${text}\x1b[0m`,
    yellow: (text: string) => `\x1b[33m${text}\x1b[0m`,
    red: (text: string) => `\x1b[31m${text}\x1b[0m`,
    cyan: (text: string) => `\x1b[36m${text}\x1b[0m`,
    magenta: (text: string) => `\x1b[35m${text}\x1b[0m`,
    dim: (text: string) => `\x1b[2m${text}\x1b[0m`,
    bold: (text: string) => `\x1b[1m${text}\x1b[0m`,
};

/**
 * Prints a success message
 */
export function success(message: string): void {
    console.log(colors.green('✓'), message);
}

/**
 * Prints an error message and exits
 */
export function error(message: string): never {
    console.error(colors.red('✗'), message);
    process.exit(1);
}

/**
 * Prints an info message
 */
export function info(message: string): void {
    console.log(colors.cyan('ℹ'), message);
}

/**
 * Prints a warning message
 */
export function warn(message: string): void {
    console.log(colors.yellow('⚠'), message);
}
