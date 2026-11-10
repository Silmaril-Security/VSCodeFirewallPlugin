export function pathIsWithin(root: string, candidate: string): boolean;

export function resolvePortableQaPolicy(
  env?: NodeJS.ProcessEnv,
): {
  mode: "preflight" | "human-ui";
  allowLaunch: boolean;
  allowNormalTrustHandoff: boolean;
  allowUiEnableHandoff: boolean;
  handoffs: {
    trust?: string;
    disableAi?: string;
    workspaceAi?: string;
  };
};

export function createFreshQaLayout(options: {
  privateRoot: string;
  receiptPath: string;
  policy: ReturnType<typeof resolvePortableQaPolicy>;
}): Promise<{
  root: string;
  receiptPath: string;
  home: string;
  userData: string;
  extensions: string;
  workspace: string;
  temporary: string;
  evidence: string;
  candidate: string;
  workspaceFile: string;
}>;

export function buildMinimalChildEnvironment(
  source: NodeJS.ProcessEnv,
  overrides: Record<string, string>,
): Record<string, string>;

