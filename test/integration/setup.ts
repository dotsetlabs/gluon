/**
 * Gluon Integration Test Setup
 *
 * Utilities for running CLI commands in isolated test environments.
 * Uses execa to spawn the CLI as a real child process.
 */

import { mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { execa } from 'execa';

/** Path to the compiled CLI */
const CLI_PATH = join(import.meta.dirname, '../../dist/cli.js');

/** Base temp directory for test projects */
const TEMP_BASE = join(tmpdir(), 'gluon-integration-tests');

/** Test API URL - defaults to local server */
export const TEST_API_URL = process.env.GLUON_API_URL || 'http://localhost:3000';

/** CLI execution result */
export interface CliResult {
    exitCode: number | undefined;
    all: string | undefined;
    stdout: string;
    stderr: string;
}

/**
 * Test project context containing paths and helpers
 */
export interface TestProject {
    /** Absolute path to the test project directory */
    dir: string;
    /** Run a CLI command in this project */
    run: (...args: string[]) => Promise<CliResult>;
    /** Run a CLI command expecting it to fail */
    runExpectFail: (...args: string[]) => Promise<CliResult>;
    /** Write a file to the project */
    writeFile: (relativePath: string, content: string) => Promise<void>;
    /** Read a file from the project */
    readFile: (relativePath: string) => Promise<string>;
    /** Check if a path exists */
    exists: (relativePath: string) => Promise<boolean>;
    /** Cleanup the project directory */
    cleanup: () => Promise<void>;
}

/**
 * Creates an isolated test project in a temp directory
 */
export async function createTestProject(): Promise<TestProject> {
    // Create unique temp directory
    const id = randomBytes(8).toString('hex');
    const dir = join(TEMP_BASE, `test-${id}`);
    await mkdir(dir, { recursive: true });

    const context: TestProject = {
        dir,

        async run(...args: string[]): Promise<CliResult> {
            const result = await execa('node', [CLI_PATH, ...args], {
                cwd: dir,
                env: {
                    ...process.env,
                    GLUON_API_URL: TEST_API_URL,
                    HOME: dir,
                },
                all: true,
                reject: true,
            });
            return {
                exitCode: result.exitCode,
                all: result.all,
                stdout: result.stdout,
                stderr: result.stderr,
            };
        },

        async runExpectFail(...args: string[]): Promise<CliResult> {
            const result = await execa('node', [CLI_PATH, ...args], {
                cwd: dir,
                env: {
                    ...process.env,
                    GLUON_API_URL: TEST_API_URL,
                    HOME: dir,
                },
                all: true,
                reject: false,
            });
            return {
                exitCode: result.exitCode,
                all: result.all,
                stdout: result.stdout,
                stderr: result.stderr,
            };
        },

        async writeFile(relativePath: string, content: string): Promise<void> {
            const fullPath = join(dir, relativePath);
            const parentDir = join(fullPath, '..');
            await mkdir(parentDir, { recursive: true });
            await writeFile(fullPath, content, 'utf8');
        },

        async readFile(relativePath: string): Promise<string> {
            return readFile(join(dir, relativePath), 'utf8');
        },

        async exists(relativePath: string): Promise<boolean> {
            try {
                await readFile(join(dir, relativePath));
                return true;
            } catch {
                return false;
            }
        },

        async cleanup(): Promise<void> {
            await rm(dir, { recursive: true, force: true });
        },
    };

    return context;
}

/**
 * Cleans up all test project directories
 */
export async function cleanupAllTestProjects(): Promise<void> {
    try {
        await rm(TEMP_BASE, { recursive: true, force: true });
    } catch {
        // Ignore if doesn't exist
    }
}

/**
 * Checks if the test server is running
 */
export async function isTestServerRunning(): Promise<boolean> {
    try {
        const response = await fetch(`${TEST_API_URL}/health`);
        return response.ok;
    } catch {
        return false;
    }
}
