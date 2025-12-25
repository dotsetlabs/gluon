/**
 * Hooks Module Tests
 *
 * Tests for HookManager functionality including lifecycle hooks,
 * stream hooks, and transform hooks.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
    HookManager,
    createHookManager,
    type HookContext,
} from '../../src/hooks.js';

describe('Hooks Module', () => {
    let manager: HookManager;

    beforeEach(() => {
        manager = createHookManager();
    });

    describe('createHookManager', () => {
        it('should create a new HookManager instance', () => {
            const m = createHookManager();
            expect(m).toBeInstanceOf(HookManager);
        });
    });

    describe('Hook Context', () => {
        it('should create context with session ID, command and args', () => {
            const ctx = manager.createContext('ses_test', 'npm', ['start']);
            expect(ctx.sessionId).toBe('ses_test');
            expect(ctx.command).toBe('npm');
            expect(ctx.args).toEqual(['start']);
            expect(ctx.startTime).toBeLessThanOrEqual(Date.now());
        });

        it('should initialize context data map', () => {
            const ctx = manager.createContext('ses_test', 'npm', []);
            expect(ctx.data).toBeInstanceOf(Map);
            expect(ctx.data.size).toBe(0);
        });

        it('should return context via getContext', () => {
            manager.createContext('ses_test', 'node', ['server.js']);
            const ctx = manager.getContext();
            expect(ctx).not.toBeNull();
            expect(ctx?.sessionId).toBe('ses_test');
        });

        it('should update context with process ID', () => {
            manager.createContext('ses_test', 'npm', []);
            manager.setProcessId(1234);
            const ctx = manager.getContext();
            expect(ctx?.pid).toBe(1234);
        });
    });

    describe('Lifecycle Hooks', () => {
        it('should register beforeStart hook', () => {
            const hook = () => { };
            manager.on('beforeStart', hook);
            expect(manager.getHookCount().beforeStart).toBe(1);
        });

        it('should register afterStart hook', () => {
            const hook = () => { };
            manager.on('afterStart', hook);
            expect(manager.getHookCount().afterStart).toBe(1);
        });

        it('should register beforeStop hook', () => {
            const hook = () => { };
            manager.on('beforeStop', hook);
            expect(manager.getHookCount().beforeStop).toBe(1);
        });

        it('should register afterStop hook', () => {
            const hook = () => { };
            manager.on('afterStop', hook);
            expect(manager.getHookCount().afterStop).toBe(1);
        });

        it('should execute lifecycle hooks with context', async () => {
            let executed = false;
            let receivedCtx: HookContext | undefined;

            manager.on('beforeStart', (ctx) => {
                executed = true;
                receivedCtx = ctx;
            });

            manager.createContext('ses_test', 'npm', ['test']);
            await manager.executeLifecycle('beforeStart');

            expect(executed).toBe(true);
            expect(receivedCtx).toBeDefined();
            expect(receivedCtx!.sessionId).toBe('ses_test');
        });

        it('should remove lifecycle hook with off()', () => {
            const hook = () => { };
            manager.on('beforeStart', hook);
            expect(manager.getHookCount().beforeStart).toBe(1);

            manager.off('beforeStart', hook);
            expect(manager.getHookCount().beforeStart).toBe(0);
        });
    });

    describe('Stream Hooks', () => {
        it('should register stdout observer hook', () => {
            const hook = () => { };
            manager.on('stdout', hook);
            expect(manager.getHookCount().stdout).toBe(1);
        });

        it('should register stderr observer hook', () => {
            const hook = () => { };
            manager.on('stderr', hook);
            expect(manager.getHookCount().stderr).toBe(1);
        });

        it('should execute stream hooks with buffer', () => {
            let received: Buffer | undefined;
            manager.on('stdout', (chunk) => {
                received = chunk;
            });

            manager.createContext('ses_test', 'npm', []);
            const testData = Buffer.from('test output');
            manager.executeStream('stdout', testData);

            expect(received).toBeDefined();
            expect(received!.toString()).toBe('test output');
        });
    });

    describe('Transform Hooks', () => {
        it('should register stdout transform hook', () => {
            const hook = () => undefined;
            manager.onTransform('stdout', hook);
            expect(manager.getHookCount().stdoutTransform).toBe(1);
        });

        it('should register stderr transform hook', () => {
            const hook = () => undefined;
            manager.onTransform('stderr', hook);
            expect(manager.getHookCount().stderrTransform).toBe(1);
        });

        it('should apply transform that modifies content', () => {
            manager.onTransform('stdout', (chunk) => {
                return Buffer.from(chunk.toString().toUpperCase());
            });

            manager.createContext('ses_test', 'npm', []);
            const result = manager.applyTransforms('stdout', Buffer.from('hello'));

            expect(result).not.toBeNull();
            expect(result?.toString()).toBe('HELLO');
        });

        it('should return null when transform suppresses content', () => {
            manager.onTransform('stdout', () => null);

            manager.createContext('ses_test', 'npm', []);
            const result = manager.applyTransforms('stdout', Buffer.from('secret'));

            expect(result).toBeNull();
        });

        it('should pass through when transform returns undefined', () => {
            manager.onTransform('stdout', () => undefined);

            manager.createContext('ses_test', 'npm', []);
            const result = manager.applyTransforms('stdout', Buffer.from('pass'));

            expect(result?.toString()).toBe('pass');
        });

        it('should remove transform hook with offTransform()', () => {
            const hook = () => undefined;
            manager.onTransform('stdout', hook);
            expect(manager.getHookCount().stdoutTransform).toBe(1);

            manager.offTransform('stdout', hook);
            expect(manager.getHookCount().stdoutTransform).toBe(0);
        });
    });

    describe('Stream Transform', () => {
        it('should create transform stream', () => {
            const transform = manager.createStreamTransform('stdout');
            expect(transform).toBeDefined();
            expect(typeof transform.pipe).toBe('function');
        });
    });

    describe('clear()', () => {
        it('should remove all registered hooks', () => {
            manager.on('beforeStart', () => { });
            manager.on('afterStop', () => { });
            manager.on('stdout', () => { });
            manager.onTransform('stderr', () => undefined);

            manager.clear();

            const counts = manager.getHookCount();
            expect(counts.beforeStart).toBe(0);
            expect(counts.afterStop).toBe(0);
            expect(counts.stdout).toBe(0);
            expect(counts.stderrTransform).toBe(0);
        });
    });

    describe('getHookCount()', () => {
        it('should return counts for all hook types', () => {
            const counts = manager.getHookCount();

            expect(counts).toHaveProperty('beforeStart');
            expect(counts).toHaveProperty('afterStart');
            expect(counts).toHaveProperty('beforeStop');
            expect(counts).toHaveProperty('afterStop');
            expect(counts).toHaveProperty('stdout');
            expect(counts).toHaveProperty('stderr');
            expect(counts).toHaveProperty('stdoutTransform');
            expect(counts).toHaveProperty('stderrTransform');
        });
    });
});
