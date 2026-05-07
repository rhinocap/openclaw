---
summary: "Follow-up plan for finishing the shared channel ingress refactor without breaking plugin SDK compatibility"
read_when:
  - Refactoring channel ingress access decisions or bundled channel plugin authorization
  - Maintaining plugin SDK compatibility while migrating bundled channel runtimes
  - Reviewing channel ingress redaction, AccessFacts projection, access groups, or event authorization
title: "Channel ingress refactor plan"
sidebarTitle: "Channel ingress refactor"
---

# Channel ingress refactor plan

The shared channel ingress work centralizes message-channel authorization behind
a generic decision graph while preserving the older plugin SDK contracts that
third-party plugins may already use.

The goal is to finish the migration without turning the compatibility layer
into a second channel runtime. Core owns generic ingress policy only. Plugins
own transport facts, platform identity normalization, API lookups, pairing
replies, command replies, reactions, typing, media, history, and user-facing
copy.

## Current PR Boundary

The current channel ingress PR should stay focused on:

- shared ingress kernel, SDK facade, decisions, projection, and docs
- bundled channel runtime migrations that are already part of the branch
- reviewer fixes for Telegram callback command auth, Signal access groups,
  group allowlist fallback, and `origin-subject` identity matching
- compatibility preservation for old plugin-facing shapes
- focused parity, redaction, SDK, docs, and changed-gate verification

Do not block the current PR on broad helper extraction. Repeated adapter and
reason-mapping glue is real, but extracting it now would make the behavioral
refactor harder to review. Treat helper extraction and wrapper deletion as
follow-up PRs after the migrated shapes are stable.

## Principles

- Core receives selected facts and policy slices, not whole config objects,
  stores, clients, network hooks, or platform defaults.
- Core must not contain Discord, Google Chat, iMessage, LINE, Mattermost,
  Matrix, Microsoft Teams, Nextcloud Talk, Signal, Slack, Telegram, WhatsApp,
  Zalo, or other bundled plugin ids or policy defaults.
- Plugins normalize platform identities locally before handing match material
  to `resolveChannelIngressState(...)`.
- Raw sender ids, phone numbers, emails, usernames, and raw allowlist entries
  may exist only in resolver input and adapter match material.
- Serialized state, decisions, diagnostics, snapshots, and `AccessFacts` use
  opaque ids, counts, reason codes, and redacted match ids.
- Route, sender, command, event, and activation gates stay separate.
- Command authorization must not be replaced by sender or route authorization.
- Compatibility shims can adapt old plugin-facing shapes to the new model.
  Bundled runtime paths should consume ingress decisions directly.

## Desired Architecture

Bundled plugin runtime path:

```text
platform event
  -> verify webhook, socket, or event authenticity locally
  -> normalize sender, conversation, route, mention, and membership facts locally
  -> resolveChannelIngressState(...)
  -> decideChannelIngress(...)
  -> plugin performs pairing, reply, ack, history, and media side effects
  -> turn kernel receives projected redacted AccessFacts
```

Third-party compatibility path:

```text
old SDK helper call
  -> compatibility shim
  -> shared ingress-compatible decision or projection where safe
  -> old return shape preserved
```

## Phase 0 Freeze Compatibility Contract

Define the compatibility surface explicitly and cover it with contract tests.
Older third-party plugins should keep compiling and keep receiving usable
compatibility values.

Keep stable:

- existing `AccessFacts` fields downstream code may read
- deprecated `allowFrom` arrays, returning empty or redacted compatibility
  values where raw values are no longer safe
- `commands.authorizers` fallback where old callers still provide it
- existing command-auth and security-runtime exports used by third-party
  plugins
- existing group-access helper exports

Mark the new ingress API as experimental:

- keep `openclaw/plugin-sdk/channel-ingress` exported
- document it as a runtime helper for migrated channel plugins
- avoid promising long-term stability for every internal type until bundled
  migrations settle

Add compatibility tests:

- fake old-style plugin input still produces usable `AccessFacts`
- command authorization remains available through old helper shapes
- turn context values still project old fields where callers expect them
- tests use generic fake plugins, not bundled plugin internals

Output:

- existing plugins keep compiling
- new ingress model can evolve internally
- compatibility behavior is covered by tests

## Phase 1 Stabilize Shared Ingress Kernel

Keep `src/channels/message-access/*` narrow. It should own only:

- allowlist resolution
- access-group expansion and match diagnostics
- redacted state
- route gates
- sender gates
- command gates
- event gates
- activation and mention gates
- `AccessFacts` projection
- admission mapping

Normalize the decision shape so all decisions expose:

- `admission`: `dispatch`, `skip`, `observe`, `drop`, or
  `pairing-required`
- `decision`: `allow`, `block`, or `pairing`
- ordered gate graph
- decisive gate id
- stable reason code
- redacted diagnostics

Redaction is mandatory. Tests should serialize representative state, decisions,
diagnostics, snapshots, and `AccessFacts`, then assert raw sender ids, phone
numbers, emails, usernames, and allowlist values are absent.

Output:

- shared kernel is generic, testable, and security-reviewable
- SDK facade wraps the kernel without leaking plugin-specific policy

## Phase 2 Extract Reusable Helpers Later

Do this after the current PR, not inside it. The purpose is to reduce migrated
plugin glue once the direct ingress decision shape has proven itself.

Potential helper groups:

- subject and adapter builders for stable ids, phone/e164, multi-identifier
  subjects, dangerous mutable usernames or emails, wildcard matching, and
  opaque entry id generation
- reason mapping helpers for common DM policy, group policy, pairing-required,
  empty allowlist, not allowlisted, disabled, and access-group diagnostic
  cases
- policy assembly helpers for DM policy plus pairing store, group allowlists
  with optional `allowFrom` fallback, command owner/group authorizers, route
  sender policies, and mention activation
- compatibility projection helpers so old SDK compatibility mapping remains in
  one place

Promotion rule:

- only promote a helper to the SDK after at least three bundled plugins converge
  on the same exact pattern
- keep helpers plugin-neutral and redaction-preserving
- avoid hiding channel-specific semantics behind a shared reason string too
  early

Output:

- bundled migrations get smaller in follow-up PRs
- per-channel reason-mapping boilerplate shrinks
- compatibility code is visibly isolated

## Phase 3 Finish Bundled Plugin Migration

For each bundled channel plugin, migrate to the same pattern:

1. Normalize platform facts locally.
2. Create subject identifiers, conversation facts, event auth mode, route facts,
   mention facts, selected allowlists, and access-group membership facts.
3. Call `resolveChannelIngressState(...)`; raw values enter only here.
4. Call `decideChannelIngress(...)`.
5. Use the decision directly for dispatch, drop, pairing, observe, and skip.
6. Use gate selectors only for secondary behavior:
   - command gate controls command authorization
   - activation gate controls mention skip
   - sender gate controls legacy log text
   - event gate controls reactions, buttons, and callbacks
7. Stop translating back to old local helper shapes where no external consumer
   needs them.
8. Keep platform side effects local.

Suggested migration order:

1. Simple or static channels: QA Channel, IRC, LINE, Zalo, Zalo Personal.
2. Shared DM/group policy channels: WhatsApp, Signal, iMessage/BlueBubbles,
   Matrix.
3. Route-heavy channels: Slack, Mattermost, Microsoft Teams, Google Chat,
   Nextcloud Talk.
4. Callback and command-sensitive channels: Telegram last or near-last, because
   it is the best stress test for command, event, and activation separation.

Output:

- bundled plugins use the new ingress model directly
- compatibility wrappers remain for third-party plugins, not internal runtime
  paths

## Phase 4 Preserve Third Party SDK Compatibility

Keep old SDK exports implemented as adapters where safe. Existing helpers such
as command auth, security-runtime group access, and `AccessFacts` projection can
call or mirror the ingress kernel, but should preserve old return shapes.

Rules:

- do not force third-party plugins to migrate immediately
- old plugin code should continue to compile and behave the same
- add deprecation comments, not breakage
- guide callers toward ingress decisions instead of raw `allowFrom`
- guide callers toward command authorization fields instead of
  `commands.authorizers`
- guide callers toward reason codes and diagnostics instead of raw allowlist
  inspection

Add SDK compatibility fixtures:

- fake third-party plugin using old helpers
- fake migrated plugin using new ingress helpers
- both compile and produce usable turn context

Output:

- third-party plugin authors are not broken
- bundled code is modernized
- deprecation path is explicit

## Phase 5 Delete Transitional Bundled Glue

Once bundled runtime paths consume ingress decisions directly, remove wrappers
that only exist for migrated internal callsites.

Look for:

- local `accessFromIngress(...)` wrappers used only inside one plugin
- repeated `mapXReasonCode(...)` boilerplate where a shared mapping is now
  proven safe
- old `senderAllowedForCommands` recomputation after the command gate already
  exists
- duplicated `effectiveAllowFrom` calculations used only for legacy logging
- tests that prove only obsolete wrapper shape and have no external consumer

Keep:

- platform normalization
- subject and adapter creation
- route fact construction
- ingress state assembly
- side-effect handling
- behavior tests for policy parity, redaction, command/event separation, and
  channel-specific semantics

Output:

- net plugin LOC starts falling
- new channels require less authorization code
- old compatibility is isolated to SDK shims

## Verification Strategy

For each migrated channel, require parity tests for the behavior that channel
already promised. Avoid generic assumptions such as all `open` policies needing
wildcards; encode the old channel contract exactly.

DM policy:

- disabled blocks
- open preserves the previous channel behavior
- allowlist permits matching sender
- pairing emits `pairing-required` only for pairable DM events
- non-pairable events do not create pairing challenges

Group policy:

- disabled blocks
- open allows sender while still respecting mention gating where applicable
- empty allowlist blocks when policy says allowlist
- matching allowlist permits
- mismatched allowlist blocks
- `groupAllowFrom` fallback behavior matches previous channel semantics

Command authorization:

- normal message access is separate from control-command authorization
- group control commands block when command gate denies
- callbacks and buttons keep command authorization separate from route
  authorization

Event authorization:

- reactions, buttons, and callbacks do not start pairing
- route-only events require route gates and bypass sender only intentionally
- `origin-subject` events match the intended normalized identity semantics

Mention activation:

- mention hit dispatches
- mention miss skips, not observe-dispatches
- authorized text command can bypass mention where channel policy allows

Redaction:

- serialized state, decision, diagnostics, and `AccessFacts` do not contain raw
  sender ids, phone numbers, emails, usernames, or raw allowlist values

Access groups:

- static `message.senders` group works for DM and group paths
- channel-specific dynamic group works only where the plugin provides
  membership facts
- missing, unsupported, and failed groups produce diagnostics and fail closed
  where appropriate

## Verification Commands

Local targeted loop:

```sh
pnpm test src/channels/message-access/message-access.test.ts src/channels/message-access/projection.test.ts src/channels/message-access/conformance.test.ts src/plugin-sdk/channel-ingress.test.ts src/plugin-sdk/access-groups.test.ts
pnpm test extensions/<channel>/src/...
pnpm plugin-sdk:api:check
pnpm config:docs:check
pnpm exec oxfmt --check --threads=1 <changed-files>
git diff --check
```

Before landing broad migration:

- use Testbox for broad changed gates or full checks when the touched surface
  fans out widely
- require CI proof for the exact head SHA on relevant channel and runtime
  shards

## Current PR Exit Criteria

- Bundled hot inbound paths in the PR use ingress decisions.
- Third-party-facing old exports still compile and have contract tests.
- Compatibility projections keep deprecated fields redacted or empty where raw
  values are not safe.
- `origin-subject`, access groups, Telegram callbacks, and group fallback
  behavior are covered.
- Docs distinguish stable compatibility shims from experimental ingress helpers.
- Redaction tests cover core plus representative migrated plugins.
- Local changed gate or Testbox equivalent is green for the touched surface.

## Final Exit Criteria

- All bundled channel plugins use shared ingress decisions on hot inbound paths.
- No bundled runtime path recomputes sender or command authorization after
  ingress has already decided it, except where platform side effects require
  extra local facts.
- Old SDK helper exports still compile and have compatibility tests.
- New ingress SDK docs clearly distinguish stable compatibility shims from
  experimental ingress helpers.
- Redaction tests cover core plus representative migrated plugins.
- Follow-up cleanup PRs delete transitional wrappers and reduce net plugin LOC.
