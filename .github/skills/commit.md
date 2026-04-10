# Commit Convention Skills

## Format Pattern

```
<type>(<module>): <short description>
```

## Types

| Type | Use When | Example |
|------|----------|---------|
| `feat` | New feature or capability | `feat(papers): add pdf upload endpoint` |
| `fix` | Bug fix | `fix(reviews): correct null pointer on empty reviews` |
| `refactor` | Code restructuring, no behavior change | `refactor(agent-kit): update x variable to y+5%` |
| `docs` | Documentation changes | `docs(api): update auth endpoint examples` |
| `test` | Adding or updating tests | `test(database): add integration tests for reviews` |
| `chore` | Maintenance, dependencies, tooling | `chore(deps): upgrade prisma to v5` |
| `style` | Code formatting, semicolons, etc | `style(web): fix eslint warnings` |
| `perf` | Performance improvements | `perf(search): optimize query with index` |
| `ci` | CI/CD changes | `ci(github): add staging deployment workflow` |

## Module Names

Use these standardized module identifiers:

| Module | Scope |
|--------|-------|
| `api` | Backend REST API |
| `web` | Frontend Next.js app |
| `agent-worker` | AI agent processing queue |
| `database` | Schema, migrations, queries |
| `papers` | Paper management domain |
| `reviews` | Review system domain |
| `agent-config` | Agent configuration domain |
| `search` | Search and discovery |
| `auth` | Authentication & authorization |
| `shared` | Shared packages/utilities |
| `infra` | Infrastructure, Docker, scripts |
| `deps` | Dependencies only |
| `*` | Multiple modules (use sparingly) |

## Description Guidelines

1. **Use imperative mood** - "add" not "added" or "adds"
2. **Lowercase first letter**
3. **No period at the end**
4. **Max 72 characters** for the summary line
5. **Be specific** - mention what changed, not just "update code"

## Good Examples

```
feat(papers): implement pdf text extraction pipeline
fix(reviews): handle null confidence scores from ai agents
refactor(agent-config): split monolithic prompt into reusable parts
docs(api): add openapi spec for agent endpoints
test(database): add seed data for development
chore(infra): update docker compose volumes for persistence
perf(search): add gin index on papers keywords array
```

## Bad Examples

```
feat: stuff                    # Missing module, vague description
feat(api): Added new endpoint  # Past tense, capitalized
fix(web).                      # Wrong separator, ends with period
refactor(): updated code       # Empty module, past tense
chore: update                  # Too vague
```

## Multi-Line Commits (Optional Body)

For complex changes, add a body after a blank line:

```
feat(agent-worker): implement chain-of-thought review generation

- Add structured reasoning steps to review output
- Implement confidence scoring per claim
- Ground all citations to source text positions

Closes #42
```

## Breaking Changes

Add `!` before the colon for breaking changes:

```
feat(api)!: change reviews response schema
refactor(database)!: rename agent_configs to agent_configurations
```

Or use `BREAKING CHANGE:` in the body.

## Quick Reference

```bash
# Template to copy
git commit -m "type(module): description"

# Examples for copy-paste
git commit -m "feat(papers): add batch upload endpoint"
git commit -m "fix(auth): correct jwt expiration check"
git commit -m "refactor(reviews): extract scoring logic to service"
git commit -m "docs(context): update agent workflow diagram"
```

## Commit Validation

If using commitlint, configuration should be:

```js
// commitlint.config.js
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'scope-enum': [2, 'always', [
      'api', 'web', 'agent-worker', 'database', 
      'papers', 'reviews', 'agent-config', 'search', 
      'auth', 'shared', 'infra', 'deps', '*'
    ]],
    'subject-case': [2, 'always', 'lower-case'],
  }
};
```

## Automation Script

Add to `package.json` scripts:

```json
{
  "scripts": {
    "commit": "git cz",
    "commit:check": "commitlint --from HEAD~1 --to HEAD --verbose"
  }
}
```
