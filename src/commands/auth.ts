import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import { cloudClient } from '../cloud/client.js';
import {
    isAuthenticated,
    loadCredentials,
    saveCredentials,
    clearCredentials,
    isCloudLinked,
    loadCloudConfig,
} from '../cloud/auth.js';

export function registerAuthCommands(program: Command) {
    /**
     * login command
     */
    program
        .command('login')
        .description('Authenticate with Gluon Cloud')
        .action(async () => {
            try {
                if (await isAuthenticated()) {
                    const credentials = await loadCredentials();
                    success(`Already logged in as ${credentials?.email}`);
                    return;
                }

                info('Authenticating with Gluon Cloud...');

                const { deviceCode, userCode, verificationUri, expiresIn, interval } = await cloudClient.getDeviceCode();

                console.log();
                console.log(colors.bold('  1. Open this URL in your browser:'));
                console.log(`     ${colors.cyan(verificationUri)}`);
                console.log();
                console.log(colors.bold('  2. Enter this code:'));
                console.log(`     ${colors.green(colors.bold(userCode))}`);
                console.log();
                console.log(colors.dim(`  Code expires in ${Math.floor(expiresIn / 60)} minutes.`));
                console.log();

                // Poll for token
                process.stdout.write(colors.dim('  Waiting for authorization'));
                const startTime = Date.now();
                const pollInterval = Math.max(interval, 5) * 1000;

                while (Date.now() - startTime < expiresIn * 1000) {
                    await new Promise(resolve => setTimeout(resolve, pollInterval));
                    process.stdout.write('.');

                    try {
                        const response = await cloudClient.pollDeviceToken(deviceCode);

                        if (response.status === 'complete' && response.user && response.tokens) {
                            console.log(colors.green(' ✓'));
                            console.log();

                            // Save credentials
                            await saveCredentials({
                                accessToken: response.tokens.accessToken,
                                refreshToken: response.tokens.refreshToken,
                                expiresAt: new Date(response.tokens.expiresAt * 1000).toISOString(),
                                email: response.user.email,
                                userId: response.user.id,
                            });

                            success('Logged in successfully!');
                            console.log();
                            console.log('  Email:', colors.cyan(response.user.email));
                            console.log('  Name:', response.user.name || colors.dim('(not set)'));
                            console.log();
                            return;
                        }

                        if (response.status === 'slow_down') {
                            // Increase interval
                            await new Promise(resolve => setTimeout(resolve, 5000));
                        }
                        // status === 'pending' - continue polling
                    } catch (err: any) {
                        const message = err.message || '';
                        if (message.includes('expired') || message.includes('denied')) {
                            console.log(colors.red(' ✗'));
                            console.log();
                            error(message);
                        }
                        throw err;
                    }
                }

                console.log(colors.red(' ✗'));
                console.log();
                error('Authorization timed out. Please try again.');
            } catch (err: any) {
                error(err.message);
            }
        });

    /**
     * logout command
     */
    program
        .command('logout')
        .description('Sign out and clear credentials')
        .action(async () => {
            try {
                await clearCredentials();
                success('Logged out successfully.');
            } catch (err: any) {
                error(err.message);
            }
        });

    /**
     * whoami command
     */
    program
        .command('whoami')
        .description('Show current authenticated user')
        .action(async () => {
            try {
                const credentials = await loadCredentials();
                if (!credentials) {
                    info('Not logged in. Run "gln login" to authenticate.');
                    return;
                }

                info(`Logged in as: ${colors.cyan(credentials.email)}`);
                info(`User ID: ${colors.dim(credentials.userId)}`);

                if (await isCloudLinked()) {
                    const config = await loadCloudConfig();
                    info(`Linked Project: ${colors.green(config?.projectId || 'Unknown')}`);
                } else {
                    info('Project state: Local only');
                }
            } catch (err: any) {
                error(err.message);
            }
        });
}
