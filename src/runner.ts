/**
 * Gluon Process Runner
 *
 * Wraps child processes with security monitoring hooks.
 * Similar to Axion's injector but adds telemetry collection and stream monitoring.
 *
 * Key Features:
 * - Spawns child processes with inherited environment
 * - Intercepts stdout/stderr for secret detection
 * - Forwards signals for graceful shutdown
 * - Collects telemetry throughout process lifecycle
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { type HookManager, createHookManager } from './hooks.js';
import { type TelemetryCollector, generateSessionId } from './telemetry.js';
import { type GluonConfig } from './config.js';

/**
 * Options for running a monitored process
 */
export interface RunOptions {
    /** Environment variables to merge with process.env */
    env?: Record<string, string>;
    /** Working directory for the child process */
    cwd?: string;
    /** Whether to use shell (useful for complex commands) */
    shell?: boolean;
    /** Hook manager to use (creates new if not provided) */
    hookManager?: HookManager;
    /** Telemetry collector to use */
    telemetry?: TelemetryCollector;
    /** Whether to pass through stdio (default: true) */
    passThrough?: boolean;
}

/**
 * Result of a monitored run
 */
export interface RunResult {
    /** Exit code of the process */
    exitCode: number;
    /** Signal that killed the process, if any */
    signal?: string;
    /** Session ID for correlating telemetry */
    sessionId: string;
    /** Duration in milliseconds */
    durationMs: number;
}

/**
 * Signals to forward to child process
 */
const FORWARDED_SIGNALS: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];

/**
 * Runs a command with security monitoring
 *
 * This function:
 * 1. Creates a hook context for the run
 * 2. Executes beforeStart hooks
 * 3. Spawns the command as a child process
 * 4. Pipes stdout/stderr through monitoring hooks
 * 5. Sets up signal forwarding for graceful shutdown
 * 6. Executes afterStop hooks when process exits
 * 7. Returns a promise with the exit code and telemetry
 *
 * @param command - The command to execute
 * @param args - Arguments to pass to the command
 * @param options - Run options including hooks and telemetry
 * @returns Promise resolving to run result
 */
export async function run(
    command: string,
    args: string[],
    options: RunOptions = {}
): Promise<RunResult> {
    const hookManager = options.hookManager ?? createHookManager();
    const sessionId = generateSessionId();
    const startTime = Date.now();

    // Create hook context
    const context = hookManager.createContext(sessionId, command, args);

    // Record process start
    options.telemetry?.recordProcessStart(command, args);

    // Execute beforeStart hooks
    await hookManager.executeLifecycle('beforeStart');

    return new Promise((resolve, reject) => {
        // Merge environment: process.env as base, then overlay custom vars
        const mergedEnv = {
            ...process.env,
            ...options.env,
            // Add Gluon session ID so child process can correlate
            GLUON_SESSION_ID: sessionId,
        };

        // Determine stdio configuration
        const usePassThrough = options.passThrough !== false;

        // Spawn the child process
        const child: ChildProcess = spawn(command, args, {
            env: mergedEnv,
            cwd: options.cwd ?? process.cwd(),
            stdio: usePassThrough ? ['inherit', 'pipe', 'pipe'] : 'inherit',
            shell: options.shell ?? false,
        });

        // Update context with PID
        if (child.pid) {
            hookManager.setProcessId(child.pid);
        }

        // Signal handlers for forwarding to child
        const signalHandlers: Map<NodeJS.Signals, () => void> = new Map();

        /**
         * Sets up signal forwarding from parent to child process
         */
        function setupSignalForwarding(): void {
            for (const signal of FORWARDED_SIGNALS) {
                const handler = () => {
                    if (child.pid) {
                        child.kill(signal);
                    }
                };
                signalHandlers.set(signal, handler);
                process.on(signal, handler);
            }
        }

        /**
         * Removes all signal handlers to prevent memory leaks
         */
        function cleanupSignalHandlers(): void {
            for (const [signal, handler] of signalHandlers) {
                process.removeListener(signal, handler);
            }
            signalHandlers.clear();
        }

        // Set up stream monitoring if using pipe mode
        if (usePassThrough && child.stdout && child.stderr) {
            // Create transform streams for monitoring
            const stdoutTransform = hookManager.createStreamTransform('stdout');
            const stderrTransform = hookManager.createStreamTransform('stderr');

            // Pipe through transforms to process stdout/stderr
            child.stdout.pipe(stdoutTransform).pipe(process.stdout);
            child.stderr.pipe(stderrTransform).pipe(process.stderr);
        }

        // Set up signal forwarding
        setupSignalForwarding();

        // Execute afterStart hooks
        hookManager.executeLifecycle('afterStart').catch(err => {
            console.error('[Gluon] afterStart hook error:', err);
        });

        // Handle spawn errors (e.g., command not found)
        child.on('error', async (error) => {
            cleanupSignalHandlers();

            options.telemetry?.record(
                'process_error',
                `Failed to start: ${error.message}`,
                { command, error: error.message },
                'error'
            );

            await hookManager.executeLifecycle('afterStop');

            reject(new Error(`Failed to start command "${command}": ${error.message}`));
        });

        // Handle child process exit
        child.on('close', async (code, signal) => {
            cleanupSignalHandlers();

            const endTime = Date.now();
            const durationMs = endTime - startTime;

            // Execute beforeStop hooks
            await hookManager.executeLifecycle('beforeStop');

            // Calculate exit code
            let exitCode: number;
            if (signal) {
                // Child was killed by a signal
                const signalCodes: Record<string, number> = {
                    SIGINT: 130,
                    SIGTERM: 143,
                    SIGHUP: 129,
                };
                exitCode = signalCodes[signal] ?? 128;
            } else {
                exitCode = code ?? 0;
            }

            // Record process stop
            options.telemetry?.recordProcessStop(exitCode, signal ?? undefined);

            // Execute afterStop hooks
            await hookManager.executeLifecycle('afterStop');

            resolve({
                exitCode,
                signal: signal ?? undefined,
                sessionId,
                durationMs,
            });
        });
    });
}

/**
 * Creates a monitored runner with pre-configured hooks and telemetry
 */
export function createRunner(
    config: GluonConfig,
    telemetry?: TelemetryCollector
): (command: string, args: string[], env?: Record<string, string>) => Promise<RunResult> {
    const hookManager = createHookManager();

    return (command: string, args: string[], env?: Record<string, string>) => {
        return run(command, args, {
            env,
            hookManager,
            telemetry,
        });
    };
}

/**
 * Runs a shell command with monitoring
 *
 * @param commandString - Full command string (e.g., "npm run dev")
 * @param options - Run options
 * @returns Promise resolving to run result
 */
export function runShell(
    commandString: string,
    options: Omit<RunOptions, 'shell'> = {}
): Promise<RunResult> {
    const shell = process.platform === 'win32' ? 'cmd.exe' : '/bin/sh';
    const shellArgs = process.platform === 'win32' ? ['/c', commandString] : ['-c', commandString];

    return run(shell, shellArgs, { ...options, shell: false });
}
