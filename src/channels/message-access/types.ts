import type { AccessGroupConfig } from "../../config/types.access-groups.js";
import type { ChatChannelId } from "../ids.js";
import type { InboundImplicitMentionKind, InboundMentionFacts } from "../mention-gating.js";

declare const CHANNEL_INGRESS_PLUGIN_ID: unique symbol;

export type ChannelIngressPluginId = string & {
  readonly [CHANNEL_INGRESS_PLUGIN_ID]: true;
};

export type ChannelIngressChannelId = ChatChannelId | ChannelIngressPluginId;

export type ChannelIngressIdentifierKind =
  | "stable-id"
  | "username"
  | "email"
  | "phone"
  | "role"
  | `plugin:${string}`;

export type MatchableIdentifier = {
  opaqueId: string;
  kind: ChannelIngressIdentifierKind;
  dangerous?: boolean;
  sensitivity?: "normal" | "pii";
};

export type InternalMatchMaterial = MatchableIdentifier & {
  value: string;
};

export type InternalChannelIngressSubject = {
  identifiers: InternalMatchMaterial[];
};

export type ChannelIngressNormalizedEntry = {
  opaqueEntryId: string;
  kind: ChannelIngressIdentifierKind;
  dangerous?: boolean;
  sensitivity?: "normal" | "pii";
};

export type InternalNormalizedEntry = ChannelIngressNormalizedEntry & {
  value: string;
};

export type RedactedIngressEntryDiagnostic = {
  opaqueEntryId?: string;
  reasonCode: IngressReasonCode;
};

export type RedactedIngressMatch = {
  matched: boolean;
  matchedEntryIds: string[];
};

export type ChannelIngressNormalizeResult = {
  matchable: ChannelIngressNormalizedEntry[];
  invalid: RedactedIngressEntryDiagnostic[];
  disabled: RedactedIngressEntryDiagnostic[];
};

export type InternalChannelIngressNormalizeResult = Omit<
  ChannelIngressNormalizeResult,
  "matchable"
> & {
  matchable: InternalNormalizedEntry[];
};

export type InternalChannelIngressAdapter = {
  normalizeEntries(params: {
    entries: readonly string[];
    context: "dm" | "group" | "route" | "command";
    accountId: string;
  }): InternalChannelIngressNormalizeResult | Promise<InternalChannelIngressNormalizeResult>;

  matchSubject(params: {
    subject: InternalChannelIngressSubject;
    entries: readonly InternalNormalizedEntry[];
    context: "dm" | "group" | "route" | "command";
  }): RedactedIngressMatch | Promise<RedactedIngressMatch>;
};

export type AccessGroupMembershipFact =
  | {
      kind: "matched";
      groupName: string;
      source: "static" | "dynamic";
      matchedEntryIds: string[];
    }
  | {
      kind: "not-matched";
      groupName: string;
      source: "static" | "dynamic";
    }
  | {
      kind: "missing" | "unsupported" | "failed";
      groupName: string;
      source: "static" | "dynamic";
      reasonCode: IngressReasonCode;
      diagnosticId?: string;
    };

export type ResolvedIngressAllowlist = {
  rawEntryCount: number;
  normalizedEntries: ChannelIngressNormalizedEntry[];
  invalidEntries: RedactedIngressEntryDiagnostic[];
  disabledEntries: RedactedIngressEntryDiagnostic[];
  matchedEntryIds: string[];
  hasConfiguredEntries: boolean;
  hasMatchableEntries: boolean;
  hasWildcard: boolean;
  accessGroups: {
    referenced: string[];
    matched: string[];
    missing: string[];
    unsupported: string[];
    failed: string[];
  };
  match: RedactedIngressMatch;
};

export type RedactedIngressAllowlistFacts = {
  configured: boolean;
  matched: boolean;
  reasonCode: IngressReasonCode;
  matchedEntryIds: string[];
  invalidEntryCount: number;
  disabledEntryCount: number;
  accessGroups: ResolvedIngressAllowlist["accessGroups"];
};

export type RouteGateState =
  | "not-configured"
  | "matched"
  | "not-matched"
  | "disabled"
  | "lookup-failed";

export type RouteSenderPolicy = "inherit" | "replace" | "deny-when-empty";

export type RouteGateFacts = {
  id: string;
  kind: "route" | "routeSender" | "membership" | "ownerAllowlist" | "nestedAllowlist";
  gate: RouteGateState;
  effect: "allow" | "block-dispatch" | "ignore";
  precedence: number;
  senderPolicy: RouteSenderPolicy;
  senderAllowFrom?: Array<string | number>;
  match?: RedactedIngressMatch;
};

export type ResolvedRouteGateFacts = Omit<RouteGateFacts, "senderAllowFrom"> & {
  senderAllowlist?: ResolvedIngressAllowlist;
};

export type ChannelIngressEventInput = {
  kind:
    | "message"
    | "reaction"
    | "button"
    | "postback"
    | "native-command"
    | "slash-command"
    | "system";
  authMode: "inbound" | "command" | "origin-subject" | "route-only" | "none";
  mayPair: boolean;
  originSubject?: InternalChannelIngressSubject;
};

export type RedactedChannelIngressEvent = Omit<ChannelIngressEventInput, "originSubject"> & {
  hasOriginSubject: boolean;
  originSubjectMatched: boolean;
};

export type ChannelIngressStateInput = {
  channelId: ChannelIngressChannelId;
  accountId: string;
  subject: InternalChannelIngressSubject;
  conversation: {
    kind: "direct" | "group" | "channel";
    id: string;
    parentId?: string;
    threadId?: string;
    title?: string;
  };
  adapter: InternalChannelIngressAdapter;
  accessGroups?: Record<string, AccessGroupConfig>;
  accessGroupMembership?: readonly AccessGroupMembershipFact[];
  routeFacts?: RouteGateFacts[];
  mentionFacts?: InboundMentionFacts;
  event: ChannelIngressEventInput;
  allowlists: {
    dm?: Array<string | number>;
    group?: Array<string | number>;
    commandOwner?: Array<string | number>;
    commandGroup?: Array<string | number>;
    pairingStore?: Array<string | number>;
  };
};

export type ChannelIngressPolicyInput = {
  dmPolicy: "pairing" | "allowlist" | "open" | "disabled";
  groupPolicy: "allowlist" | "open" | "disabled";
  groupAllowFromFallbackToAllowFrom?: boolean;
  mutableIdentifierMatching?: "disabled" | "enabled";
  activation?: {
    requireMention: boolean;
    allowTextCommands: boolean;
  };
  command?: {
    useAccessGroups?: boolean;
    allowTextCommands: boolean;
    hasControlCommand: boolean;
    modeWhenAccessGroupsOff?: "allow" | "deny" | "configured";
  };
};

export type IngressGatePhase = "route" | "sender" | "command" | "event" | "activation";

export type IngressGateKind =
  | "route"
  | "routeSender"
  | "dmSender"
  | "groupSender"
  | "membership"
  | "ownerAllowlist"
  | "nestedAllowlist"
  | "command"
  | "event"
  | "mention";

export type IngressGateEffect =
  | "allow"
  | "block-dispatch"
  | "block-command"
  | "skip"
  | "observe"
  | "ignore";

export type IngressReasonCode =
  | "allowed"
  | "route_blocked"
  | "route_sender_empty"
  | "dm_policy_disabled"
  | "dm_policy_open"
  | "dm_policy_allowlisted"
  | "dm_policy_pairing_required"
  | "dm_policy_not_allowlisted"
  | "group_policy_disabled"
  | "group_policy_open"
  | "group_policy_allowed"
  | "group_policy_empty_allowlist"
  | "group_policy_not_allowlisted"
  | "command_authorized"
  | "control_command_unauthorized"
  | "event_authorized"
  | "event_unauthorized"
  | "event_pairing_not_allowed"
  | "sender_not_required"
  | "origin_subject_missing"
  | "origin_subject_not_matched"
  | "activation_allowed"
  | "activation_skipped"
  | "access_group_missing"
  | "access_group_unsupported"
  | "access_group_failed"
  | "mutable_identifier_disabled"
  | "no_policy_match";

export type AccessGraphGate = {
  id: string;
  phase: IngressGatePhase;
  kind: IngressGateKind;
  effect: IngressGateEffect;
  allowed: boolean;
  reasonCode: IngressReasonCode;
  match?: RedactedIngressMatch;
  allowlist?: RedactedIngressAllowlistFacts;
  sender?: {
    policy: ChannelIngressPolicyInput["dmPolicy"] | ChannelIngressPolicyInput["groupPolicy"];
  };
  command?: {
    useAccessGroups: boolean;
    allowTextCommands: boolean;
    modeWhenAccessGroupsOff?: "allow" | "deny" | "configured";
    shouldBlockControlCommand: boolean;
  };
  event?: RedactedChannelIngressEvent;
  activation?: {
    hasMentionFacts: boolean;
    requireMention: boolean;
    allowTextCommands: boolean;
    shouldSkip: boolean;
    canDetectMention?: boolean;
    wasMentioned?: boolean;
    hasAnyMention?: boolean;
    implicitMentionKinds?: readonly InboundImplicitMentionKind[];
    effectiveWasMentioned?: boolean;
  };
};

export type AccessGraph = {
  gates: AccessGraphGate[];
};

export type ChannelIngressState = {
  channelId: ChannelIngressChannelId;
  accountId: string;
  conversationKind: "direct" | "group" | "channel";
  event: RedactedChannelIngressEvent;
  mentionFacts?: InboundMentionFacts;
  routeFacts: ResolvedRouteGateFacts[];
  allowlists: {
    dm: ResolvedIngressAllowlist;
    pairingStore: ResolvedIngressAllowlist;
    group: ResolvedIngressAllowlist;
    commandOwner: ResolvedIngressAllowlist;
    commandGroup: ResolvedIngressAllowlist;
  };
};

export type ChannelIngressAdmission = "dispatch" | "observe" | "skip" | "drop" | "pairing-required";

export type RedactedIngressDiagnostics = {
  decisiveGateId?: string;
  reasonCode: IngressReasonCode;
};

export type ChannelIngressDecision = {
  admission: ChannelIngressAdmission;
  decision: "allow" | "block" | "pairing";
  decisiveGateId: string;
  reasonCode: IngressReasonCode;
  graph: AccessGraph;
  diagnostics: RedactedIngressDiagnostics;
};

export type ChannelIngressSideEffectResult =
  | { kind: "none" }
  | { kind: "pairing-reply-sent" }
  | { kind: "pairing-reply-failed"; errorCode?: string }
  | { kind: "command-reply-sent" }
  | { kind: "command-reply-failed"; errorCode?: string }
  | { kind: "pending-history-recorded" }
  | { kind: "local-event-handled" };
