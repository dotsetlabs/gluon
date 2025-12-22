/**
 * Gluon Hooks Module
 *
 * Manages runtime hooks for intercepting and monitoring application behavior.
 * Hooks are registered for different lifecycle events and stream transformations.
 *
 * Hook Types:
 * - beforeStart: Called before spawning the child process
 * - afterStart: Called after process has started
 * - beforeStop: Called before process termination
 * - afterStop: Called after process has terminated
 * - stdout: Transform/inspect stdout data
 * - stderr: Transform/inspect stderr data
 */

import { Transform, type TransformCallback } from 'node:stream';

/**
 * Hook callback for lifecycle events
 */
export type LifecycleHook = (context: HookContext) => void | Promise<void>;

/**
 * Hook callback for stream data
 */
export type StreamHook = (chunk: Buffer, context: HookContext) => void;

/**
 * Context passed to all hooks
 */
export interface HookContext {
    /** Session ID for this run */
    sessionId: string;
    /** Command being executed */
    command: string;
    /** Command arguments */
    args: string[];
    /** Process ID if available */
    pid?: number;
    /** Start timestamp */
    startTime: number;
    /** Custom data that hooks can share */
    data: Map<string, unknown>;
}

/**
 * Registered hooks container
 */
interface RegisteredHooks {
    beforeStart: LifecycleHook[];
    afterStart: LifecycleHook[];
    beforeStop: LifecycleHook[];
    afterStop: LifecycleHook[];
    stdout: StreamHook[];
    stderr: StreamHook[];
}

/**
 * Hook manager for registering and executing hooks
 */
export class HookManager {
    private hooks: RegisteredHooks = {
        beforeStart: [],
        afterStart: [],
        beforeStop: [],
        afterStop: [],
        stdout: [],
        stderr: [],
    };

    private context: HookContext | null = null;

    /**
     * Registers a lifecycle hook
     */
    on(event: 'beforeStart' | 'afterStart' | 'beforeStop' | 'afterStop', hook: LifecycleHook): void;
    /**
     * Registers a stream hook
     */
    on(event: 'stdout' | 'stderr', hook: StreamHook): void;
    on(event: keyof RegisteredHooks, hook: LifecycleHook | StreamHook): void {
        const hooks = this.hooks[event] as (LifecycleHook | StreamHook)[];
        hooks.push(hook);
    }

    /**
     * Removes a hook
     */
    off(event: keyof RegisteredHooks, hook: LifecycleHook | StreamHook): void {
        const hooks = this.hooks[event] as (LifecycleHook | StreamHook)[];
        const index = hooks.indexOf(hook);
        if (index !== -1) {
            hooks.splice(index, 1);
        }
    }

    /**
     * Creates and sets the hook context for a run
     */
    createContext(sessionId: string, command: string, args: string[]): HookContext {
        this.context = {
            sessionId,
            command,
            args,
            startTime: Date.now(),
            data: new Map(),
        };
        return this.context;
    }

    /**
     * Updates the context with process ID
     */
    setProcessId(pid: number): void {
        if (this.context) {
            this.context.pid = pid;
        }
    }

    /**
     * Gets the current context
     */
    getContext(): HookContext | null {
        return this.context;
    }

    /**
     * Executes lifecycle hooks
     */
    async executeLifecycle(
        event: 'beforeStart' | 'afterStart' | 'beforeStop' | 'afterStop'
    ): Promise<void> {
        if (!this.context) return;

        const hooks = this.hooks[event];
        for (const hook of hooks) {
            await hook(this.context);
        }
    }

    /**
     * Executes stream hooks synchronously
     */
    executeStream(event: 'stdout' | 'stderr', chunk: Buffer): void {
        if (!this.context) return;

        const hooks = this.hooks[event];
        for (const hook of hooks) {
            hook(chunk, this.context);
        }
    }

    /**
     * Creates a transform stream that passes data through hooks
     */
    createStreamTransform(event: 'stdout' | 'stderr'): Transform {
        return new Transform({
            transform: (chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) => {
                this.executeStream(event, chunk);
                callback(null, chunk);
            },
        });
    }

    /**
     * Clears all registered hooks
     */
    clear(): void {
        for (const key of Object.keys(this.hooks) as (keyof RegisteredHooks)[]) {
            this.hooks[key] = [];
        }
    }

    /**
     * Gets the count of registered hooks
     */
    getHookCount(): Record<keyof RegisteredHooks, number> {
        return {
            beforeStart: this.hooks.beforeStart.length,
            afterStart: this.hooks.afterStart.length,
            beforeStop: this.hooks.beforeStop.length,
            afterStop: this.hooks.afterStop.length,
            stdout: this.hooks.stdout.length,
            stderr: this.hooks.stderr.length,
        };
    }
}

/**
 * Global hook manager instance
 */
let globalHookManager: HookManager | null = null;

/**
 * Gets or creates the global hook manager
 */
export function getHookManager(): HookManager {
    if (!globalHookManager) {
        globalHookManager = new HookManager();
    }
    return globalHookManager;
}

/**
 * Creates a new hook manager instance
 */
export function createHookManager(): HookManager {
    return new HookManager();
}
