export type CellValue = boolean | string;

export interface ComparisonRow {
  feature: string;
  artifactKeeper: CellValue;
  artifactoryPro: CellValue;
  artifactoryEnterprise: CellValue;
}

export interface ComparisonColumn {
  key: keyof Omit<ComparisonRow, "feature">;
  label: string;
}

export const columns: ComparisonColumn[] = [
  { key: "artifactKeeper", label: "Artifact Keeper" },
  { key: "artifactoryPro", label: "Artifactory Pro (~$400/mo)" },
  { key: "artifactoryEnterprise", label: "Artifactory Enterprise (~$1,400/mo+)" },
];

export const rows: ComparisonRow[] = [
  {
    feature: "All package formats",
    artifactKeeper: true,
    artifactoryPro: true,
    artifactoryEnterprise: true,
  },
  {
    feature: "Security scanning",
    artifactKeeper: true,
    artifactoryPro: false,
    artifactoryEnterprise: true,
  },
  {
    feature: "High availability",
    artifactKeeper: true,
    artifactoryPro: false,
    artifactoryEnterprise: true,
  },
  {
    feature: "Replication",
    artifactKeeper: true,
    artifactoryPro: false,
    artifactoryEnterprise: true,
  },
  {
    feature: "LDAP/SAML/OIDC",
    artifactKeeper: true,
    artifactoryPro: true,
    artifactoryEnterprise: true,
  },
  {
    feature: "REST API",
    artifactKeeper: true,
    artifactoryPro: true,
    artifactoryEnterprise: true,
  },
  {
    feature: "Migration tooling",
    artifactKeeper: true,
    artifactoryPro: false,
    artifactoryEnterprise: false,
  },
  {
    feature: "Self-hosted",
    artifactKeeper: true,
    artifactoryPro: true,
    artifactoryEnterprise: true,
  },
  {
    feature: "Price",
    artifactKeeper: "$0",
    artifactoryPro: "~$400/month",
    artifactoryEnterprise: "~$1,400/month+",
  },
];
