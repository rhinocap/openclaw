import { mergeDmAllowFromSources } from "openclaw/plugin-sdk/allow-from";
import {
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngress,
  findChannelIngressCommandGate,
  resolveChannelIngressState,
  type ChannelIngressAdapterEntry,
  type ChannelIngressDecision,
  type ChannelIngressPolicyInput,
  type ChannelIngressState,
  type ChannelIngressSubject,
} from "openclaw/plugin-sdk/channel-ingress";
import { normalizeMatrixAllowList, resolveMatrixAllowListMatch } from "./allowlist.js";

type MatrixCommandAuthorizer = {
  configured: boolean;
  allowed: boolean;
};

type MatrixMonitorAllowListMatch = {
  allowed: boolean;
  matchKey?: string;
  matchSource?: "wildcard" | "id" | "prefixed-id" | "prefixed-user";
};

type MatrixMonitorAccessState = {
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
  effectiveRoomUsers: string[];
  groupAllowConfigured: boolean;
  directAllowMatch: MatrixMonitorAllowListMatch;
  roomUserMatch: MatrixMonitorAllowListMatch | null;
  groupAllowMatch: MatrixMonitorAllowListMatch | null;
  commandAuthorizers: [MatrixCommandAuthorizer, MatrixCommandAuthorizer, MatrixCommandAuthorizer];
  ingressState: ChannelIngressState;
  ingressDecision: ChannelIngressDecision;
};

const MATRIX_CHANNEL_ID = createChannelIngressPluginId("matrix");

function normalizeMatrixEntry(raw?: string | null): string | null {
  return normalizeMatrixAllowList([raw ?? ""])[0] ?? null;
}

function createMatrixIngressAdapterEntry(value: string, index: number): ChannelIngressAdapterEntry {
  return {
    opaqueEntryId: `entry-${index + 1}`,
    kind: "stable-id",
    value,
  };
}

const matrixIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry(entry, index) {
    const normalized = normalizeMatrixEntry(entry);
    return normalized ? [createMatrixIngressAdapterEntry(normalized, index)] : [];
  },
  getSubjectMatchKeys(identifier) {
    if (identifier.kind !== "stable-id") {
      return [];
    }
    const normalized = normalizeMatrixEntry(identifier.value);
    if (!normalized || normalized === "*") {
      return [];
    }
    return [
      `stable-id:${normalized}`,
      `stable-id:matrix:${normalized}`,
      `stable-id:user:${normalized}`,
    ];
  },
});

function createMatrixIngressSubject(senderId: string): ChannelIngressSubject {
  const normalized = normalizeMatrixEntry(senderId);
  return {
    identifiers: normalized
      ? [
          {
            opaqueId: "sender-id",
            kind: "stable-id",
            value: normalized,
          },
        ]
      : [],
  };
}

function resolveMatrixIngressGroupPolicy(params: {
  groupPolicy: "open" | "allowlist" | "disabled";
  effectiveGroupAllowFrom: string[];
  effectiveRoomUsers: string[];
}): ChannelIngressPolicyInput["groupPolicy"] {
  if (params.groupPolicy === "disabled") {
    return "disabled";
  }
  if (params.effectiveRoomUsers.length > 0) {
    return "allowlist";
  }
  if (params.groupPolicy === "allowlist" && params.effectiveGroupAllowFrom.length > 0) {
    return "allowlist";
  }
  return "open";
}

function resolveMatrixIngressGroupAllowFrom(params: {
  groupPolicy: "open" | "allowlist" | "disabled";
  effectiveGroupAllowFrom: string[];
  effectiveRoomUsers: string[];
}): string[] {
  if (params.effectiveRoomUsers.length > 0) {
    return params.effectiveRoomUsers;
  }
  if (params.groupPolicy === "allowlist" && params.effectiveGroupAllowFrom.length > 0) {
    return params.effectiveGroupAllowFrom;
  }
  return [];
}

export async function resolveMatrixMonitorAccessState(params: {
  allowFrom: Array<string | number>;
  storeAllowFrom: Array<string | number>;
  dmPolicy?: "open" | "pairing" | "allowlist" | "disabled";
  groupPolicy?: "open" | "allowlist" | "disabled";
  groupAllowFrom: Array<string | number>;
  roomUsers: Array<string | number>;
  senderId: string;
  isRoom: boolean;
  accountId?: string;
  eventKind?: "message" | "reaction";
}): Promise<MatrixMonitorAccessState> {
  const dmPolicy = params.dmPolicy ?? "pairing";
  const groupPolicy = params.groupPolicy ?? "open";
  const configuredAllowFrom = normalizeMatrixAllowList(params.allowFrom);
  const effectiveAllowFrom = normalizeMatrixAllowList(
    mergeDmAllowFromSources({
      allowFrom: configuredAllowFrom,
      storeAllowFrom: params.storeAllowFrom,
      dmPolicy,
    }),
  );
  const effectiveGroupAllowFrom = normalizeMatrixAllowList(params.groupAllowFrom);
  const effectiveRoomUsers = normalizeMatrixAllowList(params.roomUsers);
  const commandAllowFrom = params.isRoom ? [] : effectiveAllowFrom;

  const directAllowMatch = resolveMatrixAllowListMatch({
    allowList: effectiveAllowFrom,
    userId: params.senderId,
  });
  const roomUserMatch =
    params.isRoom && effectiveRoomUsers.length > 0
      ? resolveMatrixAllowListMatch({
          allowList: effectiveRoomUsers,
          userId: params.senderId,
        })
      : null;
  const groupAllowMatch =
    effectiveGroupAllowFrom.length > 0
      ? resolveMatrixAllowListMatch({
          allowList: effectiveGroupAllowFrom,
          userId: params.senderId,
        })
      : null;
  const commandAllowMatch =
    commandAllowFrom.length > 0
      ? resolveMatrixAllowListMatch({
          allowList: commandAllowFrom,
          userId: params.senderId,
        })
      : null;
  const ingressGroupPolicy = resolveMatrixIngressGroupPolicy({
    groupPolicy,
    effectiveGroupAllowFrom,
    effectiveRoomUsers,
  });
  const ingressState = await resolveChannelIngressState({
    channelId: MATRIX_CHANNEL_ID,
    accountId: params.accountId ?? "default",
    subject: createMatrixIngressSubject(params.senderId),
    conversation: {
      kind: params.isRoom ? "group" : "direct",
      id: params.isRoom ? "matrix-room" : "matrix-dm",
    },
    adapter: matrixIngressAdapter,
    event: {
      kind: params.eventKind ?? "message",
      authMode: "inbound",
      mayPair: !params.isRoom && (params.eventKind ?? "message") === "message",
    },
    allowlists: {
      dm: configuredAllowFrom,
      pairingStore: normalizeMatrixAllowList(params.storeAllowFrom),
      group: resolveMatrixIngressGroupAllowFrom({
        groupPolicy,
        effectiveGroupAllowFrom,
        effectiveRoomUsers,
      }),
      commandOwner: commandAllowFrom,
      commandGroup: effectiveRoomUsers.length > 0 ? effectiveRoomUsers : effectiveGroupAllowFrom,
    },
  });
  const ingressDecision = decideChannelIngress(ingressState, {
    dmPolicy,
    groupPolicy: ingressGroupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
  });

  return {
    effectiveAllowFrom,
    effectiveGroupAllowFrom,
    effectiveRoomUsers,
    groupAllowConfigured: effectiveGroupAllowFrom.length > 0,
    directAllowMatch,
    roomUserMatch,
    groupAllowMatch,
    commandAuthorizers: [
      {
        configured: commandAllowFrom.length > 0,
        allowed: commandAllowMatch?.allowed ?? false,
      },
      {
        configured: effectiveRoomUsers.length > 0,
        allowed: roomUserMatch?.allowed ?? false,
      },
      {
        configured: effectiveGroupAllowFrom.length > 0,
        allowed: groupAllowMatch?.allowed ?? false,
      },
    ],
    ingressState,
    ingressDecision,
  };
}

export function resolveMatrixMonitorCommandAccess(
  state: MatrixMonitorAccessState,
  params: {
    useAccessGroups: boolean;
    allowTextCommands: boolean;
    hasControlCommand: boolean;
  },
): { commandAuthorized: boolean; shouldBlockControlCommand: boolean } {
  const commandState: ChannelIngressState = {
    ...state.ingressState,
    event: {
      ...state.ingressState.event,
      authMode: "command",
      mayPair: false,
    },
  };
  const decision = decideChannelIngress(commandState, {
    dmPolicy: "allowlist",
    groupPolicy: "allowlist",
    groupAllowFromFallbackToAllowFrom: false,
    command: {
      useAccessGroups: params.useAccessGroups,
      allowTextCommands: params.allowTextCommands,
      hasControlCommand: params.hasControlCommand,
    },
  });
  const commandGate = findChannelIngressCommandGate(decision);
  return {
    commandAuthorized: commandGate?.allowed === true,
    shouldBlockControlCommand: commandGate?.command?.shouldBlockControlCommand === true,
  };
}
