"use strict";

function snapshotNativeState(receipt, nativeState) {
  if (!nativeState) return receipt;
  receipt.providerRequests = Array.isArray(nativeState.providerRequests)
    ? nativeState.providerRequests.slice()
    : nativeState.providerRequests;
  receipt.toolInvocations =
    nativeState.toolInvocations
      && typeof nativeState.toolInvocations === "object"
      ? { ...nativeState.toolInvocations }
      : nativeState.toolInvocations;
  receipt.providerCallCount = nativeState.providerCallCount;
  return receipt;
}

module.exports = { snapshotNativeState };
