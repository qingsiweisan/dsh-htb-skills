/**
 * dsh-htb-skills — HTB pentesting skill library plugin for DeepSeek Harness.
 *
 * Host half only. It registers a package-local skill provider named `htb`
 * over the bundled `skills/` tree through the official
 * `@deepseek-ai/dsh-skill-filesystem` provider implementation:
 *
 *   - single source of truth: skills live in this package, versioned by git;
 *   - `includeDefaultRoots: false` so this provider lists ONLY the bundled
 *     cards (the deployment's own `skill-filesystem` row keeps discovering
 *     project/user skills);
 *   - Chokidar watches the package tree, so edits hot-reload without a
 *     harness restart;
 *   - T1 cards stay model-invocable and appear in the session catalog;
 *     T2/T3 cards carry `disable-model-invocation: true` and are loaded by
 *     name (see the `htb-skill-index` card for the full domain x tier table).
 *
 * No browser half, no routes.
 */

import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FileSystemSkillProvider } from '@deepseek-ai/dsh-skill-filesystem'
import { registerSherlockTools } from './sherlock-tools.js'

/** Stable Cordis plugin name. */
export const name = 'htb-skills'

/** Wait for the host composition's skill registry and tool registry before mounting. */
export const inject = ['skills', 'tools']

/** Absolute path of the bundled skills tree inside this package. */
export function bundledSkillsRoot() {
  return join(fileURLToPath(new URL('..', import.meta.url)), 'skills')
}

/**
 * Mount the plugin: register the `htb` skill provider over the package's
 * own skills directory, plus the htb_sherlock_* model tools.
 *
 * Config:
 *   - `skillsEnabled` (default true): set false on deployments that already
 *     serve the same cards from another skill provider (~/.dsh/skills), so
 *     only the tools mount and the card names never collide.
 *   - `tokenPath` / `token`: HTB bearer token source (default
 *     ~/.dsh/htb-token.txt or $HTB_TOKEN).
 * @param ctx - host plugin context carrying `skills` and `tools`.
 */
export function apply(ctx, config) {
  config = config ?? {}
  if (config.skillsEnabled !== false) {
    const root = bundledSkillsRoot()
    ctx.skills.registerProvider((control) =>
      new FileSystemSkillProvider(ctx, control, {
        providerName: 'htb',
        includeDefaultRoots: false,
        customSkillDirs: [root],
        // Schema-required fields that are inert with includeDefaultRoots:false;
        // bundledSkillDir must resolve to an empty path so nothing is mounted
        // under the trusted `bundled` source.
        dshHome: root,
        agentsHome: root,
        bundledSkillDir: join(root, '..', '.bundled-empty'),
        watch: true,
      }),
    )
  }
  registerSherlockTools(ctx, config)
}
