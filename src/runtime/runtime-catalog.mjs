import { isProxy } from 'node:util/types';

const ERROR_CODE = 'RUNTIME_INPUT_INVALID';
const MAX_CATALOG_REVISION = 2_147_483_647;
// Keep the runtime catalog inside the connection bootstrap's accepted OS range.
const MIN_WINDOWS_BUILD = 17_763;
const MAX_WINDOWS_BUILD = 99_999;
const MAX_ARTIFACTS = 32;
const MAX_ARTIFACT_BYTES = 256 * 1024 ** 2;
const MAX_EXPANDED_BYTES = 32 * 1024 ** 3;
const MAX_ID_LENGTH = 64;
const MAX_VERSION_LENGTH = 64;
const MAX_URL_LENGTH = 2_048;
const MAX_REDIRECT_ORIGINS = 4;

const ROOT_FIELDS = Object.freeze([
  'schemaVersion',
  'catalogRevision',
  'platform',
  'artifacts',
  'profiles',
]);
const PLATFORM_FIELDS = Object.freeze(['os', 'architecture', 'minimumBuild']);
const ARTIFACT_FIELDS = Object.freeze([
  'id',
  'version',
  'url',
  'redirectOrigins',
  'bytes',
  'maximumExpandedBytes',
  'sha256',
  'packaging',
  'signerRule',
  'verificationCommandId',
]);
const PROFILE_FIELDS = Object.freeze(['id', 'artifacts', 'dependencies']);
const PROFILE_IDS = Object.freeze(['core', 'base']);

const ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;
const SHA256_PATTERN = /^[0-9A-F]{64}$/;

function failInput() {
  const error = new TypeError(ERROR_CODE);
  error.code = ERROR_CODE;
  throw error;
}

function readExactRecord(input, fields) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    failInput();
  }

  const names = Object.getOwnPropertyNames(input);
  if (names.length !== fields.length || !fields.every((field) => names.includes(field))) {
    failInput();
  }

  const values = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      failInput();
    }
    values[field] = descriptor.value;
  }
  return values;
}

function readExactArray(input, minimumLength, maximumLength) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || !Array.isArray(input)
    || Object.getPrototypeOf(input) !== Array.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) {
    failInput();
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(input, 'length');
  if (
    lengthDescriptor === undefined
    || !Object.hasOwn(lengthDescriptor, 'value')
    || !Number.isInteger(lengthDescriptor.value)
    || lengthDescriptor.value < minimumLength
    || lengthDescriptor.value > maximumLength
  ) {
    failInput();
  }

  const length = lengthDescriptor.value;
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== length + 1) failInput();

  const values = [];
  for (let index = 0; index < length; index += 1) {
    const name = String(index);
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (
      descriptor === undefined
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      failInput();
    }
    values.push(descriptor.value);
  }

  if (!names.every((name) => name === 'length' || /^(?:0|[1-9][0-9]*)$/.test(name))) {
    failInput();
  }
  return values;
}

function assertCanonicalId(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_ID_LENGTH
    || !ID_PATTERN.test(value)
  ) {
    failInput();
  }
}

function assertCanonicalVersion(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_VERSION_LENGTH
    || !VERSION_PATTERN.test(value)
  ) {
    failInput();
  }
}

function assertCanonicalArtifactUrl(value, version) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_URL_LENGTH
    || value !== value.trim()
    || /[\x00-\x20\x7F]/.test(value)
  ) {
    failInput();
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    failInput();
  }

  const versionPattern = new RegExp(
    `(?:^|[^0-9])${version.replaceAll('.', '\\.')}([^0-9]|$)`,
  );

  if (
    parsed.protocol !== 'https:'
    || parsed.href !== value
    || parsed.hostname.length === 0
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.port !== ''
    || parsed.search !== ''
    || parsed.hash !== ''
    || parsed.pathname.includes('%')
    || parsed.pathname.toLowerCase().includes('latest')
    || !versionPattern.test(parsed.pathname)
    || !parsed.pathname.endsWith('.zip')
  ) {
    failInput();
  }
  return parsed.origin;
}

function assertCanonicalHttpsOrigin(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_URL_LENGTH
    || value !== value.trim()
    || /[\x00-\x20\x7F]/.test(value)
  ) {
    failInput();
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    failInput();
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.hostname.length === 0
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.port !== ''
    || parsed.pathname !== '/'
    || parsed.search !== ''
    || parsed.hash !== ''
    || parsed.origin !== value
  ) {
    failInput();
  }
}

function validateRedirectOrigins(input, sourceOrigin) {
  const values = readExactArray(input, 0, MAX_REDIRECT_ORIGINS);
  for (const value of values) assertCanonicalHttpsOrigin(value);
  if (new Set(values).size !== values.length || values.includes(sourceOrigin)) failInput();
  return [...values].sort(compareIds);
}

function compareIds(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function freezeDeep(value) {
  if (Array.isArray(value)) {
    for (const child of value) freezeDeep(child);
  } else {
    for (const child of Object.values(value)) {
      if (child !== null && typeof child === 'object') freezeDeep(child);
    }
  }
  return Object.freeze(value);
}

function validatePlatform(input) {
  const platform = readExactRecord(input, PLATFORM_FIELDS);
  if (
    platform.os !== 'windows'
    || platform.architecture !== 'x64'
    || !Number.isInteger(platform.minimumBuild)
    || platform.minimumBuild < MIN_WINDOWS_BUILD
    || platform.minimumBuild > MAX_WINDOWS_BUILD
  ) {
    failInput();
  }

  return {
    os: platform.os,
    architecture: platform.architecture,
    minimumBuild: platform.minimumBuild,
  };
}

function validateArtifact(input) {
  const artifact = readExactRecord(input, ARTIFACT_FIELDS);
  assertCanonicalId(artifact.id);
  assertCanonicalVersion(artifact.version);
  const sourceOrigin = assertCanonicalArtifactUrl(artifact.url, artifact.version);
  const redirectOrigins = validateRedirectOrigins(artifact.redirectOrigins, sourceOrigin);
  assertCanonicalId(artifact.signerRule);
  assertCanonicalId(artifact.verificationCommandId);

  if (
    !Number.isSafeInteger(artifact.bytes)
    || artifact.bytes < 1
    || artifact.bytes > MAX_ARTIFACT_BYTES
    || !Number.isSafeInteger(artifact.maximumExpandedBytes)
    || artifact.maximumExpandedBytes < 1
    || artifact.maximumExpandedBytes > MAX_EXPANDED_BYTES
    || typeof artifact.sha256 !== 'string'
    || !SHA256_PATTERN.test(artifact.sha256)
    || artifact.packaging !== 'zip'
  ) {
    failInput();
  }

  return {
    id: artifact.id,
    version: artifact.version,
    url: artifact.url,
    redirectOrigins,
    bytes: artifact.bytes,
    maximumExpandedBytes: artifact.maximumExpandedBytes,
    sha256: artifact.sha256,
    packaging: artifact.packaging,
    signerRule: artifact.signerRule,
    verificationCommandId: artifact.verificationCommandId,
  };
}

function validateIdArray(input, maximumLength, { allowEmpty = false } = {}) {
  const values = readExactArray(input, allowEmpty ? 0 : 1, maximumLength);
  for (const value of values) assertCanonicalId(value);
  if (new Set(values).size !== values.length) failInput();
  return [...values].sort(compareIds);
}

function validateProfile(input) {
  const profile = readExactRecord(input, PROFILE_FIELDS);
  assertCanonicalId(profile.id);
  return {
    id: profile.id,
    artifacts: validateIdArray(profile.artifacts, MAX_ARTIFACTS),
    dependencies: validateIdArray(profile.dependencies, PROFILE_IDS.length, { allowEmpty: true }),
  };
}

function assertProfileGraph(profilesById, artifactIds) {
  for (const profile of profilesById.values()) {
    if (!profile.artifacts.every((id) => artifactIds.has(id))) failInput();
    if (!profile.dependencies.every((id) => profilesById.has(id))) failInput();
  }

  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visiting.has(id)) failInput();
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of profilesById.get(id).dependencies) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of profilesById.keys()) visit(id);

  const core = profilesById.get('core');
  const base = profilesById.get('base');
  if (
    profilesById.size !== PROFILE_IDS.length
    || core === undefined
    || base === undefined
    || core.dependencies.length !== 0
    || base.dependencies.length !== 1
    || base.dependencies[0] !== 'core'
  ) {
    failInput();
  }
}

export function validateRuntimeCatalog(input) {
  const catalog = readExactRecord(input, ROOT_FIELDS);
  if (
    catalog.schemaVersion !== 1
    || !Number.isInteger(catalog.catalogRevision)
    || catalog.catalogRevision < 1
    || catalog.catalogRevision > MAX_CATALOG_REVISION
  ) {
    failInput();
  }

  const platform = validatePlatform(catalog.platform);
  const artifactInputs = readExactArray(catalog.artifacts, 1, MAX_ARTIFACTS);
  const artifacts = artifactInputs.map(validateArtifact).sort((left, right) => compareIds(left.id, right.id));
  const artifactIds = new Set(artifacts.map(({ id }) => id));
  if (artifactIds.size !== artifacts.length) failInput();

  const profileInputs = readExactArray(catalog.profiles, PROFILE_IDS.length, PROFILE_IDS.length);
  const profiles = profileInputs.map(validateProfile);
  const profilesById = new Map(profiles.map((profile) => [profile.id, profile]));
  if (profilesById.size !== profiles.length) failInput();
  assertProfileGraph(profilesById, artifactIds);

  const canonicalProfiles = PROFILE_IDS.map((id) => profilesById.get(id));
  return freezeDeep({
    schemaVersion: catalog.schemaVersion,
    catalogRevision: catalog.catalogRevision,
    platform,
    artifacts,
    profiles: canonicalProfiles,
  });
}

export function resolveRuntimeProfiles(catalogInput, requestedProfilesInput) {
  const catalog = validateRuntimeCatalog(catalogInput);
  const requestedProfiles = validateIdArray(
    requestedProfilesInput,
    PROFILE_IDS.length,
    { allowEmpty: true },
  );
  if (!requestedProfiles.every((id) => PROFILE_IDS.includes(id))) failInput();

  const profilesById = new Map(catalog.profiles.map((profile) => [profile.id, profile]));
  const resolvedProfileIds = new Set();
  function addProfile(id) {
    if (resolvedProfileIds.has(id)) return;
    const profile = profilesById.get(id);
    if (profile === undefined) failInput();
    for (const dependency of profile.dependencies) addProfile(dependency);
    resolvedProfileIds.add(id);
  }

  addProfile('core');
  for (const id of requestedProfiles) addProfile(id);

  const profiles = PROFILE_IDS.filter((id) => resolvedProfileIds.has(id));
  const artifactIds = new Set();
  for (const profileId of profiles) {
    for (const artifactId of profilesById.get(profileId).artifacts) artifactIds.add(artifactId);
  }

  return freezeDeep({
    schemaVersion: catalog.schemaVersion,
    catalogRevision: catalog.catalogRevision,
    platform: { ...catalog.platform },
    profiles: [...profiles],
    artifacts: catalog.artifacts
      .filter(({ id }) => artifactIds.has(id))
      .map((artifact) => ({ ...artifact })),
  });
}
