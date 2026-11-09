"use strict";

function workspaceTrustAction({
  workspaceTrusted,
  allowNormalTrustHandoff,
}) {
  if (workspaceTrusted) return "continue";
  if (allowNormalTrustHandoff) return "wait-for-normal-ui-trust";
  throw new Error(
    "Synthetic profile has no normal workspace trust; strict QA stopped without prompting",
  );
}

module.exports = { workspaceTrustAction };
