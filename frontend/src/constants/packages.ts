import type { PackageType } from '../types';

/**
 * Human-readable labels for package types.
 */
export const packageTypeLabels: Record<PackageType, string> = {
  maven: 'Maven',
  gradle: 'Gradle',
  npm: 'npm',
  pypi: 'PyPI',
  nuget: 'NuGet',
  go: 'Go',
  rubygems: 'RubyGems',
  docker: 'Docker',
  helm: 'Helm',
  rpm: 'RPM',
  debian: 'Debian',
  conan: 'Conan',
  cargo: 'Cargo',
  generic: 'Generic',
};
