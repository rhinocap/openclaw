import {
  allowlistFailureReason,
  applyMutableIdentifierPolicy,
  effectiveGroupSenderAllowlist,
  redactedAllowlistDiagnostics,
} from "./allowlist.js";
import type {
  AccessGraphGate,
  ChannelIngressPolicyInput,
  ChannelIngressState,
  ResolvedIngressAllowlist,
} from "./types.js";

function gate(params: AccessGraphGate): AccessGraphGate {
  return params;
}

function gateWithAllowlist(
  params: AccessGraphGate & { allowlistSource: ResolvedIngressAllowlist },
): AccessGraphGate {
  const { allowlistSource, ...gateParams } = params;
  return gate({
    ...gateParams,
    allowlist: redactedAllowlistDiagnostics(allowlistSource, gateParams.reasonCode),
  });
}

export function senderGateForDirect(params: {
  state: ChannelIngressState;
  policy: ChannelIngressPolicyInput;
}): AccessGraphGate {
  const dm = applyMutableIdentifierPolicy(params.state.allowlists.dm, params.policy);
  const pairingStore = applyMutableIdentifierPolicy(
    params.state.allowlists.pairingStore,
    params.policy,
  );
  if (params.policy.dmPolicy === "disabled") {
    return gateWithAllowlist({
      id: "sender:dm",
      phase: "sender",
      kind: "dmSender",
      effect: "block-dispatch",
      allowed: false,
      reasonCode: "dm_policy_disabled",
      match: dm.match,
      sender: { policy: params.policy.dmPolicy },
      allowlistSource: dm,
    });
  }
  if (params.policy.dmPolicy === "open") {
    if (dm.hasWildcard) {
      return gateWithAllowlist({
        id: "sender:dm",
        phase: "sender",
        kind: "dmSender",
        effect: "allow",
        allowed: true,
        reasonCode: "dm_policy_open",
        match: dm.match,
        sender: { policy: params.policy.dmPolicy },
        allowlistSource: dm,
      });
    }
    if (dm.match.matched) {
      return gateWithAllowlist({
        id: "sender:dm",
        phase: "sender",
        kind: "dmSender",
        effect: "allow",
        allowed: true,
        reasonCode: "dm_policy_allowlisted",
        match: dm.match,
        sender: { policy: params.policy.dmPolicy },
        allowlistSource: dm,
      });
    }
    return gateWithAllowlist({
      id: "sender:dm",
      phase: "sender",
      kind: "dmSender",
      effect: "block-dispatch",
      allowed: false,
      reasonCode: "dm_policy_not_allowlisted",
      match: dm.match,
      sender: { policy: params.policy.dmPolicy },
      allowlistSource: dm,
    });
  }
  if (dm.match.matched) {
    return gateWithAllowlist({
      id: "sender:dm",
      phase: "sender",
      kind: "dmSender",
      effect: "allow",
      allowed: true,
      reasonCode: "dm_policy_allowlisted",
      match: dm.match,
      sender: { policy: params.policy.dmPolicy },
      allowlistSource: dm,
    });
  }
  if (params.policy.dmPolicy === "pairing" && pairingStore.match.matched) {
    return gateWithAllowlist({
      id: "sender:dm",
      phase: "sender",
      kind: "dmSender",
      effect: "allow",
      allowed: true,
      reasonCode: "dm_policy_allowlisted",
      match: pairingStore.match,
      sender: { policy: params.policy.dmPolicy },
      allowlistSource: pairingStore,
    });
  }
  if (params.policy.dmPolicy === "pairing" && params.state.event.mayPair) {
    return gateWithAllowlist({
      id: "sender:dm",
      phase: "sender",
      kind: "dmSender",
      effect: "block-dispatch",
      allowed: false,
      reasonCode: "dm_policy_pairing_required",
      match: dm.match,
      sender: { policy: params.policy.dmPolicy },
      allowlistSource: dm,
    });
  }
  const reasonCode =
    params.policy.dmPolicy === "pairing"
      ? "event_pairing_not_allowed"
      : (allowlistFailureReason(dm) ?? "dm_policy_not_allowlisted");
  return gateWithAllowlist({
    id: "sender:dm",
    phase: "sender",
    kind: "dmSender",
    effect: "block-dispatch",
    allowed: false,
    reasonCode,
    match: dm.match,
    sender: { policy: params.policy.dmPolicy },
    allowlistSource: dm,
  });
}

export function senderGateForGroup(params: {
  state: ChannelIngressState;
  policy: ChannelIngressPolicyInput;
}): AccessGraphGate {
  const group = effectiveGroupSenderAllowlist(params);
  if (params.policy.groupPolicy === "disabled") {
    return gateWithAllowlist({
      id: "sender:group",
      phase: "sender",
      kind: "groupSender",
      effect: "block-dispatch",
      allowed: false,
      reasonCode: "group_policy_disabled",
      match: group.match,
      sender: { policy: params.policy.groupPolicy },
      allowlistSource: group,
    });
  }
  if (params.policy.groupPolicy === "open") {
    return gateWithAllowlist({
      id: "sender:group",
      phase: "sender",
      kind: "groupSender",
      effect: "allow",
      allowed: true,
      reasonCode: "group_policy_open",
      match: group.match,
      sender: { policy: params.policy.groupPolicy },
      allowlistSource: group,
    });
  }
  if (!group.hasConfiguredEntries) {
    return gateWithAllowlist({
      id: "sender:group",
      phase: "sender",
      kind: "groupSender",
      effect: "block-dispatch",
      allowed: false,
      reasonCode: "group_policy_empty_allowlist",
      match: group.match,
      sender: { policy: params.policy.groupPolicy },
      allowlistSource: group,
    });
  }
  if (group.match.matched) {
    return gateWithAllowlist({
      id: "sender:group",
      phase: "sender",
      kind: "groupSender",
      effect: "allow",
      allowed: true,
      reasonCode: "group_policy_allowed",
      match: group.match,
      sender: { policy: params.policy.groupPolicy },
      allowlistSource: group,
    });
  }
  return gateWithAllowlist({
    id: "sender:group",
    phase: "sender",
    kind: "groupSender",
    effect: "block-dispatch",
    allowed: false,
    reasonCode: allowlistFailureReason(group) ?? "group_policy_not_allowlisted",
    match: group.match,
    sender: { policy: params.policy.groupPolicy },
    allowlistSource: group,
  });
}

export function applyEventAuthModeToSenderGate(params: {
  state: ChannelIngressState;
  senderGate: AccessGraphGate;
}): AccessGraphGate {
  if (params.state.event.authMode === "inbound" || params.senderGate.allowed) {
    return params.senderGate;
  }
  const reasonCode = "sender_not_required";
  return {
    ...params.senderGate,
    effect: "ignore",
    allowed: true,
    reasonCode,
    allowlist: params.senderGate.allowlist
      ? { ...params.senderGate.allowlist, reasonCode }
      : undefined,
  };
}
