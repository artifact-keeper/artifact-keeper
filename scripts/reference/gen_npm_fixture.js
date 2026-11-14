#!/usr/bin/env node
// Generate backend/test_fixtures/reference/npm.json.
//
// What npm's own libraries say about a corpus of package names and versions:
// `validate-npm-package-name` for names, `semver` for versions (validity,
// pre-release, and rank in SemVer precedence; equal versions share a rank).
// `formats::npm` and the version comparators are checked against this file,
// so they cannot drift from what the npm client does.
//
// Usage (uses the copies npm itself ships with):
//   NODE_PATH="$(npm root -g)/npm/node_modules" node scripts/reference/gen_npm_fixture.js \
//     > backend/test_fixtures/reference/npm.json
const semver = require('semver');
const validateName = require('validate-npm-package-name');

const names = [
  'a', 'react', 'left-pad', 'lodash.merge', 'under_score', '@scope/name', '@babel/core', '@a/b',
  '0', '0x', '-leading', '_leading', '.leading', 'trailing-', 'trailing.', 'UPPER', 'Mixed-Case',
  '@Scope/name', '@scope/Name', '@scope', '@scope/', '@/name', '@scope/a/b', 'a/b', 'a b', ' a', 'a ',
  'a%20b', 'a..b', '..', '.', 'node_modules', 'favicon.ico', 'http', 'fs', 'a~b', "a'b", 'a!b', 'a(b)',
  'a*b', 'a@b', '@scope/.name', '@scope/_name', '@.scope/name', '@_scope/name', '@scope/name.', 'café',
  'a​b', 'a'.repeat(214), 'a'.repeat(215), '@a/' + 'b'.repeat(211), '@a/' + 'b'.repeat(212), '',
  'a+b', 'a:b', 'a?b', 'a#b', 'a&b', 'a=b', 'a,b', 'a;b', 'a$b', 'a\\b', 'a|b', 'a^b', 'a`b', 'a{b}',
  'a[b]', 'a<b>', 'a"b', 'jquery', 'JSONStream', '@types/node', '@scope/~name', '~name', '@~scope/name',
];

const cores = ['0.0.0', '0.0.1', '0.1.0', '1.0.0', '1.0.1', '1.1.0', '1.2.3', '1.10.0', '1.9.0', '2.0.0', '10.0.0'];
const pres = ['', '-0', '-1', '-2', '-10', '-alpha', '-alpha.1', '-alpha.2', '-alpha.10', '-alpha.beta',
  '-beta', '-beta.2', '-beta.11', '-rc.1', '-rc', '-a.b.c', '-1a', '-a1', '-x-y', '-0.3.7', '-x.7.z.92', '-Alpha', '-RC.1'];
const builds = ['', '+build', '+build.1', '+001', '+sha.5114f85'];
const versions = new Set();
for (const c of cores) for (const p of pres) versions.add(c + p);
for (const c of cores.slice(3, 6)) for (const p of pres.slice(0, 8)) for (const b of builds) versions.add(c + p + b);
for (const v of ['1', '1.0', 'v1.0.0', '=1.0.0', '1.0.0.0', '01.0.0', '1.00.0', '1.0.0-01', '1.0.0-', '1.0.0+',
  '1.0.0-alpha..1', '1.0.0-alpha_1', ' 1.0.0', '1.0.0 ', 'latest', '', '1.0.0-rc.01', '1.0.0-0a',
  '99999999999999999999.0.0', '1.0.0-99999999999999999999', '9007199254740991.0.0', '9007199254740992.0.0',
  '1.x', '*', '1.0.0-alpha+', '1.0.0+build+2', '1.0.0-alpha.-1']) versions.add(v);

const versionRows = [...versions].sort().map((v) => {
  const strict = semver.valid(v) !== null && semver.clean(v) === v;
  return { version: v, valid: strict, loose: semver.valid(v, { loose: true }) !== null,
    prerelease: strict ? semver.prerelease(v) !== null : undefined };
});
const valid = versionRows.filter((r) => r.valid).sort((a, b) => semver.compare(a.version, b.version));
let rank = -1;
valid.forEach((row, i) => {
  if (i === 0 || semver.compare(valid[i - 1].version, row.version) !== 0) rank += 1;
  row.rank = rank;
});

const nameRows = names.map((name) => {
  const r = validateName(name);
  return { name, valid_for_new: r.validForNewPackages, valid_for_old: r.validForOldPackages };
});

process.stdout.write(JSON.stringify({
  _generated_by: 'scripts/reference/gen_npm_fixture.js',
  semver: require('semver/package.json').version,
  validate_npm_package_name: require('validate-npm-package-name/package.json').version,
  names: nameRows,
  versions: versionRows,
}, null, 1) + '\n');
