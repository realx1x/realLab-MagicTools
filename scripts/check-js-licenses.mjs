import { readFile } from 'node:fs/promises';

const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const ALLOWLIST_URL = new URL('../security/js-license-allowlist.json', import.meta.url);
const PACKAGE_NAME_PATTERN = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION_PATTERN = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$/;
const productionOnly = process.argv.length === 3 && process.argv[2] === '--production';

if (process.argv.length > 3 || (process.argv.length === 3 && !productionOnly)) {
  process.exitCode = 1;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(record, expectedKeys) {
  const actualKeys = Object.keys(record).sort();
  const sortedExpected = [...expectedKeys].sort();
  return (
    actualKeys.length === sortedExpected.length &&
    actualKeys.every((key, index) => key === sortedExpected[index])
  );
}

function isBoundedString(value, maximumLength = 256) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maximumLength &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isSafePackageName(value) {
  return isBoundedString(value) && PACKAGE_NAME_PATTERN.test(value);
}

function isSafeVersion(value) {
  return isBoundedString(value, 128) && VERSION_PATTERN.test(value);
}

function packageId(name, version) {
  return `${name}@${version}`;
}

function exceptionKey(name, version, license) {
  return JSON.stringify([name, version, license]);
}

async function readStandardInput() {
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of process.stdin) {
    totalBytes += chunk.length;
    if (totalBytes > MAX_INPUT_BYTES) {
      throw new Error('license input exceeds the fixed limit');
    }
    chunks.push(chunk);
  }
  if (totalBytes === 0) {
    throw new Error('license input is empty');
  }
  return Buffer.concat(chunks, totalBytes).toString('utf8');
}

function parseAllowlist(value) {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['schemaVersion', 'allowedLicenses', 'exceptions']) ||
    value.schemaVersion !== 1 ||
    !Array.isArray(value.allowedLicenses) ||
    value.allowedLicenses.length === 0 ||
    !Array.isArray(value.exceptions)
  ) {
    throw new Error('invalid license allowlist');
  }

  const allowedLicenses = new Set();
  for (const license of value.allowedLicenses) {
    if (!isBoundedString(license) || allowedLicenses.has(license)) {
      throw new Error('invalid allowed license');
    }
    allowedLicenses.add(license);
  }

  const exceptions = new Set();
  for (const exception of value.exceptions) {
    if (
      !isRecord(exception) ||
      !hasExactKeys(exception, ['name', 'version', 'license', 'reason']) ||
      !isSafePackageName(exception.name) ||
      !isSafeVersion(exception.version) ||
      !isBoundedString(exception.license) ||
      !isBoundedString(exception.reason, 512) ||
      allowedLicenses.has(exception.license)
    ) {
      throw new Error('invalid license exception');
    }
    const key = exceptionKey(exception.name, exception.version, exception.license);
    if (exceptions.has(key)) {
      throw new Error('duplicate license exception');
    }
    exceptions.add(key);
  }

  return { allowedLicenses, exceptions };
}

function inspectLicenses(value, policy) {
  if (!isRecord(value) || Object.keys(value).length === 0) {
    throw new Error('invalid pnpm license report');
  }

  const failures = new Set();
  const seenPackages = new Set();
  let inspectedPackages = 0;
  for (const [licenseExpression, packages] of Object.entries(value)) {
    if (!isBoundedString(licenseExpression) || !Array.isArray(packages) || packages.length === 0) {
      throw new Error('invalid pnpm license group');
    }
    for (const packageEntry of packages) {
      if (
        !isRecord(packageEntry) ||
        !isSafePackageName(packageEntry.name) ||
        !Array.isArray(packageEntry.versions) ||
        packageEntry.versions.length === 0 ||
        !Array.isArray(packageEntry.paths) ||
        packageEntry.paths.length !== packageEntry.versions.length ||
        !packageEntry.paths.every((path) => path === null || isBoundedString(path, 4096))
      ) {
        throw new Error('invalid pnpm package entry');
      }

      for (const version of packageEntry.versions) {
        if (!isSafeVersion(version)) {
          throw new Error('invalid pnpm package version');
        }
        const id = packageId(packageEntry.name, version);
        const duplicate = seenPackages.has(id);
        seenPackages.add(id);
        const licenseMatches = packageEntry.license === licenseExpression;
        const allowed = policy.allowedLicenses.has(licenseExpression);
        const excepted =
          !productionOnly &&
          policy.exceptions.has(exceptionKey(packageEntry.name, version, licenseExpression));
        if (duplicate || !licenseMatches || (!allowed && !excepted)) {
          failures.add(id);
        }
        inspectedPackages += 1;
      }
    }
  }

  if (inspectedPackages === 0) {
    throw new Error('empty pnpm license report');
  }
  return failures;
}

try {
  if (process.exitCode) {
    throw new Error('invalid command arguments');
  }
  const [allowlistText, reportText] = await Promise.all([
    readFile(ALLOWLIST_URL, 'utf8'),
    readStandardInput(),
  ]);
  const policy = parseAllowlist(JSON.parse(allowlistText));
  const failures = inspectLicenses(JSON.parse(reportText), policy);
  if (failures.size > 0) {
    console.error([...failures].sort().join('\n'));
    process.exitCode = 1;
  }
} catch {
  process.exitCode = 1;
}
