# Versioned Prompt Registry

Every role lives at `prompts/<role>/<semver>.md`. `manifest.json` is the only
runtime lookup surface and binds role, semantic version, approval status, owner,
and SHA-256. A Prompt change is a high-risk release change and requires Golden,
Adversarial, schema, and human-review gates before the manifest can advance.

Running Tasks retain their recorded Prompt version. A registry rollback affects
new Tasks only unless a safety Kill Switch explicitly terminates or replans
existing work.
