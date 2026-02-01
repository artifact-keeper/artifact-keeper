export interface PackageFormat {
  name: string;
  category: string;
}

export const packages: PackageFormat[] = [
  // Languages
  { name: "Maven", category: "Languages" },
  { name: "npm", category: "Languages" },
  { name: "PyPI", category: "Languages" },
  { name: "NuGet", category: "Languages" },
  { name: "Cargo", category: "Languages" },
  { name: "Go", category: "Languages" },
  { name: "RubyGems", category: "Languages" },
  { name: "Composer", category: "Languages" },
  { name: "Hex", category: "Languages" },
  { name: "Pub", category: "Languages" },
  { name: "CRAN", category: "Languages" },
  { name: "sbt", category: "Languages" },

  // Containers & Cloud
  { name: "Docker/OCI", category: "Containers & Cloud" },
  { name: "Helm", category: "Containers & Cloud" },
  { name: "Terraform", category: "Containers & Cloud" },
  { name: "Vagrant", category: "Containers & Cloud" },

  // ML/AI
  { name: "HuggingFace", category: "ML/AI" },
  { name: "Conda", category: "ML/AI" },

  // System Packages
  { name: "Debian/APT", category: "System Packages" },
  { name: "RPM/YUM", category: "System Packages" },
  { name: "Alpine/APK", category: "System Packages" },
  { name: "Conan", category: "System Packages" },

  // Other
  { name: "Generic", category: "Other" },
  { name: "Git LFS", category: "Other" },
  { name: "VS Code Extensions", category: "Other" },
  { name: "JetBrains Plugins", category: "Other" },
  { name: "CocoaPods", category: "Other" },
  { name: "Swift", category: "Other" },
  { name: "Chef", category: "Other" },
  { name: "Puppet", category: "Other" },
];
