---
summary: "Design and usage guide for the experimental channel ingress access API"
read_when:
  - Building or migrating a messaging channel plugin
  - Changing DM or group allowlists, route gates, command auth, event auth, or mention activation
  - Reviewing channel ingress redaction or AccessFacts projection
title: "Channel ingress API"
sidebarTitle: "Channel Ingress"
---

# Channel ingress API

Channel ingress is the access-control boundary for inbound messaging events.
It answers one question before the turn kernel runs: should this message,
command, reaction, button, postback, or native command dispatch, skip, observe,
drop, or start pairing?

Use `openclaw/plugin-sdk/channel-ingress` from channel runtime receive paths
when your plugin needs shared DM/group allowlist, route, command, event, or
mention-activation policy. The API is experimental because the bundled plugins
are still proving which policy shapes are generic enough for third-party
channels.

## Design

The ingress API is deliberately split into three layers:

- plugin adapters own platform facts and raw identity values
- core resolves redacted allowlist state and builds an access graph
- plugins perform side effects and map the decision into the turn kernel

Core never receives whole `OpenClawConfig`, stores, transport clients, webhook
objects, or platform API hooks. The plugin reads those surfaces first and passes
only selected policy slices and normalized facts into the resolver.

```text
transport event
  -> plugin verifies webhook, token, replay, and platform auth
  -> plugin resolves account, sender, conversation, route, and mention facts
  -> plugin reads caller-owned dynamic state such as pairing entries
  -> resolveChannelIngressState(...)
  -> decideChannelIngress(...) or decideChannelIngressBundle(...)
  -> plugin sends pairing, command, ack, or local-event side effects
  -> mapChannelIngressDecisionToTurnAdmission(...)
  -> turn kernel
```

This keeps channel-specific behavior plugin-owned while sharing the policy math
that otherwise drifts across every channel plugin.

## Ownership

Core owns generic policy semantics:

- DM policy: `pairing`, `allowlist`, `open`, `disabled`
- group policy: `allowlist`, `open`, `disabled`
- pairing-store entries as DM-only authorization facts
- route gates, route-sender gates, and empty-route-sender failure semantics
- command authorization from owner/group authorizers
- event authorization modes
- mention activation as `skip`, not observe-only dispatch
- mutable identifier handling
- stable reason codes, redacted diagnostics, and `AccessFacts` projection

Plugins own platform-specific facts and side effects:

- webhook signatures, bot tokens, upstream auth, replay protection, and rate limits
- sender, room, thread, guild, topic, route, or membership lookup
- platform identity normalization and subject matching
- access-group membership facts that need platform APIs
- pairing challenge delivery and pairing-store writes
- command replies, local event acknowledgements, reactions, typing, media, and history
- channel-specific logs and user-visible text

## Basic flow

Create a subject, choose an adapter, resolve state, then decide:

```ts
import {
  createChannelIngressPluginId,
  createChannelIngressStringAdapter,
  createChannelIngressSubject,
  decideChannelIngress,
  projectIngressAccessFacts,
  resolveChannelIngressState,
} from "openclaw/plugin-sdk/channel-ingress";

const subject = createChannelIngressSubject({
  opaqueId: "sender",
  kind: "stable-id",
  value: platformUserId,
});

const state = await resolveChannelIngressState({
  channelId: createChannelIngressPluginId("my-channel"),
  accountId,
  subject,
  conversation: {
    kind: "direct",
    id: dmId,
  },
  adapter: createChannelIngressStringAdapter(),
  event: {
    kind: "message",
    authMode: "inbound",
    mayPair: true,
  },
  allowlists: {
    dm: config.allowFrom,
    pairingStore: pairedSenderIds,
  },
});

const decision = decideChannelIngress(state, {
  dmPolicy: config.dmPolicy,
  groupPolicy: config.groupPolicy,
});

const accessFacts = projectIngressAccessFacts(decision);
```

`resolveChannelIngressState(...)` may be async because adapters can normalize
or match through async helpers. `decideChannelIngress(...)`,
`projectIngressAccessFacts(...)`, and gate selectors are pure.

## Redaction

Raw sender values and raw configured allowlist entries are resolver input only.
They must not appear in resolved state, decisions, diagnostics, snapshots, or
`AccessFacts`.

Use opaque ids for anything that may be serialized:

- `subject.identifiers[].opaqueId`
- `normalizedEntries[].opaqueEntryId`
- route gate `id`
- diagnostic `opaqueEntryId`
- matched entry ids

The adapter can hold raw `value` fields while resolving, but exported state uses
redacted shapes. Tests should assert that serialized state and decisions do not
contain private sender values.

## Subjects and adapters

A subject is the sender identity for one inbound event. It can contain multiple
identifiers for channels that support both stable ids and mutable names.

```ts
const subject = createChannelIngressSubject({
  identifiers: [
    { opaqueId: "sender-id", kind: "stable-id", value: userId },
    { opaqueId: "sender-name", kind: "username", value: username, dangerous: true },
  ],
});
```

Use `createChannelIngressStringAdapter(...)` for simple exact matching:

```ts
const adapter = createChannelIngressStringAdapter({
  kind: "phone",
  normalizeEntry: normalizePhone,
  normalizeSubject: normalizePhone,
  sensitivity: "pii",
});
```

Use `createChannelIngressMultiIdentifierAdapter(...)` when one configured entry
can expand into several matchable identifiers:

```ts
const adapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry(entry, index) {
    const normalized = entry.trim().toLowerCase();
    if (!normalized) {
      return [];
    }
    return [
      {
        opaqueEntryId: `entry-${index + 1}`,
        kind: normalized.startsWith("@") ? "username" : "stable-id",
        value: normalized.replace(/^@/, ""),
        dangerous: normalized.startsWith("@"),
      },
    ];
  },
});
```

Mutable or ambiguous identifiers should set `dangerous: true`. They match only
when the policy explicitly enables mutable identifier matching:

```ts
decideChannelIngress(state, {
  dmPolicy: "allowlist",
  groupPolicy: "allowlist",
  mutableIdentifierMatching: "enabled",
});
```

## State input

`ChannelIngressStateInput` is the deterministic boundary between plugin facts
and shared policy:

- `channelId`: a bundled chat channel id or `createChannelIngressPluginId(...)`
- `accountId`: the channel account being evaluated
- `subject`: the normalized sender subject
- `conversation`: direct, group, or channel conversation facts
- `adapter`: entry normalization and subject matching
- `allowlists`: selected DM, group, command, and pairing entries
- `routeFacts`: optional route gates provided by the plugin
- `accessGroups` and `accessGroupMembership`: optional precomputed group facts
- `mentionFacts`: optional mention-detection facts
- `event`: event kind and event auth mode

The resolver accepts selected policy slices, not runtime config objects. If a
plugin needs to read a pairing store, fetch room membership, or expand an
access group through a platform API, do that before calling the resolver.

## Events

Each event declares how it should be authorized:

| `authMode`       | Meaning                                                               |
| ---------------- | --------------------------------------------------------------------- |
| `inbound`        | use the sender gate for normal inbound messages                       |
| `command`        | use the command gate, common for plugin callbacks and scoped buttons  |
| `origin-subject` | require the interacting subject to match the original message subject |
| `route-only`     | bypass sender auth after route gates, for route-scoped trusted events |
| `none`           | bypass shared auth, for plugin-owned internal events                  |

Use `mayPair: false` for reactions, buttons, native commands, and callbacks
that must never start the DM pairing flow.

`origin-subject` matching compares normalized identity values in the resolver
and stores only the redacted match result in state.

## Decisions and gates

`decideChannelIngress(...)` returns a `ChannelIngressDecision`:

- `admission`: `dispatch`, `observe`, `skip`, `drop`, or `pairing-required`
- `decision`: `allow`, `block`, or `pairing`
- `reasonCode`: stable reason code for logs/tests
- `decisiveGateId`: diagnostic id of the gate that decided the result
- `graph.gates`: ordered route, sender, command, event, and activation gates
- `diagnostics`: redacted summary

Prefer typed selectors over graph-id string matching:

```ts
import {
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
} from "openclaw/plugin-sdk/channel-ingress";

const senderGate = findChannelIngressSenderGate(decision, { isGroup });
const commandGate = findChannelIngressCommandGate(decision);
```

Use `decideChannelIngressBundle(...)` when a plugin needs related decisions for
the same event shape, such as normal sender dispatch and command authorization.
The bundle keeps the policy shape explicit without forcing plugin handlers to
guess which gate was decisive.

## Route gates

Plugins can pass `routeFacts` when a channel has room, topic, guild, thread, or
nested route policy. Core only evaluates the generic gate shape:

- `gate`: `matched`, `not-matched`, `not-configured`, `disabled`, or `lookup-failed`
- `effect`: `allow`, `block-dispatch`, or `ignore`
- `senderPolicy`: `inherit`, `replace`, or `deny-when-empty`
- `senderAllowFrom`: optional route-owned sender allowlist

Use `senderPolicy: "deny-when-empty"` when a matched route must fail closed if
the route has no configured sender allowlist. Use `"replace"` when the route
sender allowlist replaces the channel-level group allowlist.

## Command authorization

Command policy is separate from sender dispatch. This lets a channel allow
inline buttons, reactions, or group callbacks by route scope while still telling
plugin handlers whether the actor is authorized to run commands.

```ts
const commandDecision = decideChannelIngress(state, {
  dmPolicy,
  groupPolicy,
  command: {
    allowTextCommands: true,
    hasControlCommand,
    useAccessGroups: true,
  },
});
```

For callbacks that pass command authorization into plugin handlers, use the
command decision or command gate. Do not replace it with a route-only boolean.

## Activation

Mention gating is modeled as an activation gate. A mention miss returns
`admission: "skip"` so the turn kernel does not treat the event as an
observe-only turn.

```ts
const decision = decideChannelIngress(state, {
  dmPolicy,
  groupPolicy,
  activation: {
    requireMention: groupRequiresMention,
    allowTextCommands: true,
  },
});
```

The plugin still owns mention extraction and passes `mentionFacts` into state
input.

## Side effects and turn admission

The decision does not perform platform side effects. The plugin sends pairing
replies, command replies, local acknowledgements, or pending-history writes,
then maps the decision and side-effect result to the turn-kernel admission:

```ts
import { mapChannelIngressDecisionToTurnAdmission } from "openclaw/plugin-sdk/channel-ingress";

const admission = mapChannelIngressDecisionToTurnAdmission(decision, {
  kind: pairingReplySent ? "pairing-reply-sent" : "none",
});
```

Keep side effects after the decision and before dispatch. This preserves
platform-specific reply behavior while letting core own the generic admission
contract.

## AccessFacts projection

`projectIngressAccessFacts(...)` converts a decision into the redacted
`AccessFacts` shape used by downstream context. The projection intentionally
keeps transitional compatibility fields such as empty `allowFrom` arrays and
empty `authorizers` arrays while new decision fields become the source of
truth.

New code should read decision, reason-code, and gate metadata rather than those
compatibility arrays.

## Tests

For core or SDK changes, cover:

- redaction: serialized state and decisions omit raw sender and allowlist values
- sender policy: DM, group, pairing, fallback, and empty-allowlist cases
- event auth: `inbound`, `command`, `origin-subject`, `route-only`, and `none`
- route gates: inherit, replace, and deny-when-empty sender policy
- activation: mention hit and mention miss
- projection: `AccessFacts` preserves expected compatibility fields
- plugin integration: at least one migrated plugin path using the API

Useful targeted commands:

```bash
pnpm test src/channels/message-access/message-access.test.ts src/channels/message-access/projection.test.ts src/channels/message-access/conformance.test.ts src/plugin-sdk/channel-ingress.test.ts
pnpm tsgo:extensions
pnpm plugin-sdk:api:check
```
