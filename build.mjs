#!/usr/bin/env node
/**
 * Bundle src/main.ts (+ the local copy of the SDK, which it imports as './sdk') into dist/pack.mjs
 * for the marketplace.
 *
 * The SDK is inlined on purpose: the module is fetched by URL and runs in a worker with no import
 * map, so any bare specifier left in it would fail to resolve. The pack has no dependencies, so the
 * source and the pinned esbuild are the whole input.
 *
 * esbuild is pinned so that anyone can check the published bundle against this source:
 *
 *   node build.mjs && git diff --exit-code dist/pack.mjs
 *
 * Usage: node build.mjs   (then node gen-manifest.mjs)
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, 'dist');
mkdirSync(outDir, { recursive: true });

execFileSync(
    'npx',
    [
        '--yes',
        'esbuild@0.25.12',
        join(here, 'src', 'main.ts'),
        '--bundle',
        '--format=esm',
        '--target=es2022',
        '--platform=browser',
        '--minify',
        '--legal-comments=inline', // never strip a licence header out of a pack
        '--log-level=warning',
        `--outfile=${join(outDir, 'pack.mjs')}`,
    ],
    { stdio: 'inherit', cwd: here },
);

console.log('Built dist/pack.mjs');
