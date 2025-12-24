import { Command } from 'commander';
import { colors, success, error, info } from '../utils/ui.js';
import { basename, join } from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import {
    generateSBOM,
    generateSPDX,
} from '../monitors/module-hooks.js';

export function registerSbomCommand(program: Command) {
    /**
     * SBOM Command
     * Generate Software Bill of Materials
     */
    program
        .command('sbom')
        .description('Generate SBOM (Software Bill of Materials)')
        .option('--format <format>', 'Output format (cyclonedx or spdx)', 'cyclonedx')
        .option('-o, --output <file>', 'Output file path')
        .option('--static', 'Generate from package.json instead of runtime')
        .action(async (options: { format: string; output?: string; static?: boolean }) => {
            try {
                const projectName = basename(process.cwd());

                if (options.static) {
                    // Static SBOM from package.json
                    info('Generating static SBOM from package.json...');

                    try {
                        const packageJsonPath = join(process.cwd(), 'package.json');
                        const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));

                        const allDeps = {
                            ...packageJson.dependencies ?? {},
                            ...packageJson.devDependencies ?? {},
                        };

                        // Generate SBOM
                        const components = Object.entries(allDeps).map(([name, version]) => ({
                            type: 'library' as const,
                            name,
                            version: String(version).replace(/^[\^~>=<]/, ''),
                            purl: `pkg:npm/${name.replace(/\//g, '%2F')}@${String(version).replace(/^[\^~>=<]/, '')}`,
                        }));

                        const sbom = options.format === 'spdx' ? {
                            spdxVersion: 'SPDX-2.3',
                            dataLicense: 'CC0-1.0',
                            SPDXID: 'SPDXRef-DOCUMENT',
                            name: projectName,
                            documentNamespace: `https://gluon.dotsetlabs.com/sbom/${projectName}/${Date.now()}`,
                            creationInfo: {
                                created: new Date().toISOString(),
                                creators: ['Tool: gluon-1.0.0'],
                            },
                            packages: components.map((c, i) => ({
                                SPDXID: `SPDXRef-Package-${i + 1}`,
                                name: c.name,
                                versionInfo: c.version,
                                downloadLocation: `https://www.npmjs.com/package/${c.name}`,
                            })),
                        } : {
                            bomFormat: 'CycloneDX',
                            specVersion: '1.5',
                            version: 1,
                            metadata: {
                                timestamp: new Date().toISOString(),
                                tools: [{ vendor: 'dotsetlabs', name: 'gluon', version: '1.0.0' }],
                                component: { type: 'application', name: projectName },
                            },
                            components,
                        };

                        const output = JSON.stringify(sbom, null, 2);

                        if (options.output) {
                            await writeFile(options.output, output, 'utf8');
                            success(`SBOM written to ${options.output}`);
                        } else {
                            console.log(output);
                        }

                        console.log();
                        info(`Found ${components.length} dependencies in package.json`);

                    } catch (err: any) {
                        error(`Failed to read package.json: ${err.message}`);
                    }
                } else {
                    // Runtime SBOM instructions
                    info('Runtime SBOM tracks dependencies loaded during execution.');
                    console.log();
                    console.log('To generate a runtime SBOM:');
                    console.log(`  ${colors.cyan('gln run --sbom -- npm start')}`);
                    console.log();
                    console.log('For static SBOM from package.json:');
                    console.log(`  ${colors.cyan('gln sbom --static')}`);
                    console.log(`  ${colors.cyan('gln sbom --static --format spdx -o sbom.spdx.json')}`);
                }
            } catch (err: any) {
                error(err.message);
            }
        });
}
