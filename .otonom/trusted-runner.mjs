// OTONOM Trusted Worker Runner — version 2026.09.7
// Self-contained, dependency-free runner for ephemeral GitHub Actions workers.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const OFFICIAL_GITHUB_KNOWN_HOSTS =
  'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

const FORBIDDEN_ENV_KEYS = new Set([
  'OTONOM_MASTER_KEY',
  'DATABASE_URL',
  'GITHUB_TOKEN',
  'GITHUB_PAT',
  'SESSION_TOKEN',
  'OTONOM_SESSION_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_ID_TOKEN',
  'GIT_SSH_COMMAND',
  'SSH_AUTH_SOCK',
  'PRIVATE_DEPLOY_KEY',
  'SENTRY_AUTH_TOKEN',
  'DOPPLER_TOKEN',
  'NEON_API_KEY',
  'NEON_STORAGE_ACCESS_KEY',
  'NEON_STORAGE_SECRET_KEY',
  'VERCEL_TOKEN',
]);

const FORBIDDEN_SECRET_NAME_PATTERNS = [
  /MASTER_KEY/i,
  /DATABASE_URL/i,
  /GITHUB.*TOKEN/i,
  /GITHUB.*PAT/i,
  /SESSION_TOKEN/i,
  /ACTIONS_ID_TOKEN/i,
  /DEPLOY_KEY/i,
  /SENTRY/i,
  /DOPPLER/i,
  /NEON/i,
  /VERCEL/i,
];

function buildSanitizedEnvironment(taskSecrets = {}) {
  const sanitized = {};
  const safeKeys = ['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'TERM', 'TMPDIR', 'TEMP', 'TMP'];
  for (const k of safeKeys) {
    if (process.env[k] !== undefined && !FORBIDDEN_ENV_KEYS.has(k)) {
      sanitized[k] = process.env[k];
    }
  }
  for (const [k, v] of Object.entries(taskSecrets)) {
    const forbidden =
      FORBIDDEN_ENV_KEYS.has(k) ||
      FORBIDDEN_SECRET_NAME_PATTERNS.some((pattern) => pattern.test(k));
    if (!forbidden && typeof v === 'string') {
      sanitized[k] = v;
    }
  }
  sanitized.OPENCODE_DISABLE_AUTOUPDATE = 'true';
  return sanitized;
}

function redactKnownSecrets(text, taskSecrets = {}) {
  let result = String(text || '');
  for (const value of Object.values(taskSecrets)) {
    if (typeof value === 'string' && value.length >= 4) {
      result = result.split(value).join('[REDACTED]');
      // Multi-line material (private keys) must also not leak line by line
      // when output is truncated or re-wrapped.
      for (const line of value.split(/\r?\n/)) {
        if (line.length >= 16) result = result.split(line).join('[REDACTED]');
      }
    }
  }
  return result;
}

// Set once bootstrap.json is parsed so a fatal error can be reported to the
// control plane over the authenticated private channel (never the public log).
let fatalReportContext = null;
let fatalReportInFlight = null;

async function reportFatalPrivately(err) {
  if (!fatalReportContext) return false;
  if (fatalReportInFlight) return fatalReportInFlight;

  fatalReportInFlight = (async () => {
    const {
      controlPlaneUrl,
      assignmentId,
      sessionToken,
      taskId,
      taskNodeId,
      leaseId,
      runId,
      attempt,
      secrets,
    } = fatalReportContext;
    const message = redactKnownSecrets(
      err && err.message ? err.message : String(err),
      secrets,
    ).slice(0, 2000);

    // Prefer the normal failed-result path: it durably transitions the run,
    // revokes authority, releases capacity, and invokes idempotent cleanup.
    try {
      const submitRes = await fetch(`${controlPlaneUrl}/api/v1/workers/submit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          taskId,
          taskNodeId,
          leaseId,
          assignmentId,
          runId,
          attempt,
          evidence: [],
          result: {
            status: 'failed',
            summary: 'Worker runner terminated before completing result collection',
            error: message,
          },
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (submitRes.ok) return true;
    } catch {}

    // If failed submission itself is unavailable, preserve a private
    // diagnostic event for later reconciliation. Never print the detail.
    try {
      await fetch(`${controlPlaneUrl}/api/v1/workers/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          assignmentId,
          eventId: `evt-fatal-${Date.now()}`,
          type: 'WORKER_FATAL',
          payload: { message },
        }),
        signal: AbortSignal.timeout(3000),
      });
    } catch {}
    return false;
  })();

  return fatalReportInFlight;
}

let terminationSignalHandled = false;
let suppressTerminationFatalReport = false;
async function handleTerminationSignal(signal) {
  // Control-plane cancellation/replanning/session revocation already owns the
  // lifecycle transition. If killing the active child also surfaces SIGTERM
  // on the runner, let main unwind through the intentional control-abort path
  // rather than creating a contradictory failed submission.
  if (suppressTerminationFatalReport) return;
  if (terminationSignalHandled) return;
  terminationSignalHandled = true;
  await reportFatalPrivately(new Error('Worker runner received ' + signal));
  process.exit(signal === 'SIGTERM' ? 143 : 130);
}

process.on('SIGTERM', () => {
  void handleTerminationSignal('SIGTERM');
});
process.on('SIGINT', () => {
  void handleTerminationSignal('SIGINT');
});

async function performDeployKeyCheckout(cloneUrl, targetSha, privateKey, destDir) {
  const nonce = Date.now() + Math.random().toString(36).slice(2, 6);
  const tempKeyPath = path.join(destDir, `.deploy_key_${nonce}`);
  const knownHostsPath = path.join(destDir, `.known_hosts_${nonce}`);

  try {
    fs.mkdirSync(destDir, { recursive: true });
    fs.writeFileSync(tempKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(knownHostsPath, OFFICIAL_GITHUB_KNOWN_HOSTS, { mode: 0o644 });

    const sshCommand = `ssh -i "${tempKeyPath}" -o StrictHostKeyChecking=yes -o UserKnownHostsFile="${knownHostsPath}"`;
    const gitEnv = { ...process.env, GIT_SSH_COMMAND: sshCommand };

    if (!fs.existsSync(path.join(destDir, '.git'))) {
      await execFileAsync('git', ['init'], { cwd: destDir, env: gitEnv });
      await execFileAsync('git', ['remote', 'add', 'origin', cloneUrl], { cwd: destDir, env: gitEnv });
    }

    await execFileAsync('git', ['fetch', '--depth=1', 'origin', targetSha], { cwd: destDir, env: gitEnv });
    await execFileAsync('git', ['checkout', '--force', targetSha], { cwd: destDir, env: gitEnv });

    const { stdout: headShaOut } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: destDir });
    const verifiedSha = headShaOut.trim();
    if (verifiedSha !== targetSha) {
      throw new Error(`Checkout SHA mismatch: expected "${targetSha}", got "${verifiedSha}"`);
    }
  } finally {
    if (fs.existsSync(tempKeyPath)) {
      try {
        fs.writeFileSync(tempKeyPath, Buffer.alloc(4096, 0));
        fs.unlinkSync(tempKeyPath);
      } catch {}
    }
    if (fs.existsSync(knownHostsPath)) {
      try {
        fs.unlinkSync(knownHostsPath);
      } catch {}
    }
  }
}

async function normalizeLocalWorkerHistory(workingDirectory, baseSha) {
  const gitEnv = { ...process.env, GIT_NO_REPLACE_OBJECTS: '1' };
  const { stdout: headOut } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: workingDirectory,
    env: gitEnv,
  });
  const currentHead = headOut.trim();
  if (currentHead === baseSha) return;

  try {
    await execFileAsync('git', ['merge-base', '--is-ancestor', baseSha, currentHead], {
      cwd: workingDirectory,
      env: gitEnv,
    });
  } catch {
    throw new Error(
      'Working tree HEAD is not a descendant of the immutable base SHA; refusing to normalize local history.',
    );
  }

  const { stdout: historyOut } = await execFileAsync(
    'git',
    ['rev-list', '--parents', baseSha + '..' + currentHead],
    { cwd: workingDirectory, env: gitEnv, maxBuffer: 1024 * 1024 },
  );
  const history = historyOut.split(/\r?\n/).filter(Boolean);
  if (history.length === 0 || history.length > 64) {
    throw new Error('Local worker history is empty or exceeds the bounded normalization limit.');
  }
  for (const line of history) {
    const parts = line.trim().split(/\s+/);
    if (parts.length !== 2) {
      throw new Error(
        'Local worker history contains a merge or malformed commit; refusing to normalize.',
      );
    }
  }

  // Workers may use local commits as an editing convenience, but commit
  // metadata/history is never trusted or sent to the target. Convert only a
  // verified linear descendant back into ordinary working-tree changes.
  await execFileAsync('git', ['reset', '--mixed', baseSha], {
    cwd: workingDirectory,
    env: gitEnv,
  });
  const { stdout: normalizedHeadOut } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: workingDirectory,
    env: gitEnv,
  });
  if (normalizedHeadOut.trim() !== baseSha) {
    throw new Error('Failed to restore immutable base SHA after local history normalization.');
  }
}

async function collectWorktreePatch(workingDirectory, baseSha) {
  await normalizeLocalWorkerHistory(workingDirectory, baseSha);
  await execFileAsync('git', ['add', '-N', '.'], { cwd: workingDirectory });
  const { stdout: rawStatus } = await execFileAsync('git', ['status', '--porcelain=v1', '-z', '-uall'], { cwd: workingDirectory });
  if (!rawStatus) return undefined;

  const entries = [];
  const tokens = rawStatus.split('\0').filter((t) => t.length > 0);
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.length >= 3) {
      const status = token.slice(0, 2);
      const filePath = token.slice(3);
      if (status.includes('R') || status.includes('C')) {
        throw new Error('UNSUPPORTED_RENAME_OR_COPY: rename/copy changes are not supported.');
      } else {
        entries.push({ status, path: filePath });
      }
    }
  }

  const changes = [];
  const changedFiles = [];
  for (const entry of entries) {
    const relPath = entry.path.replace(/\\/g, '/');
    const fullPath = path.join(workingDirectory, relPath);
    changedFiles.push(relPath);

    if (entry.status.includes('D') || !fs.existsSync(fullPath)) {
      changes.push({ path: relPath, operation: 'delete' });
      continue;
    }

    const lstat = fs.lstatSync(fullPath);
    if (lstat.isSymbolicLink() || lstat.isDirectory()) {
      throw new Error(`Unsupported file type for ${relPath}`);
    }

    const buf = fs.readFileSync(fullPath);
    for (let b = 0; b < Math.min(buf.length, 8000); b++) {
      if (buf[b] === 0) throw new Error(`Binary file modification unsupported: ${relPath}`);
    }

    const content = buf.toString('utf8');
    const contentHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    changes.push({
      path: relPath,
      operation: entry.status.includes('A') || entry.status === '??' ? 'add' : 'modify',
      content,
      contentHash,
      mode: (lstat.mode & 0o111) !== 0 ? '100755' : '100644',
    });
  }

  const { stdout: diff } = await execFileAsync('git', ['diff', baseSha], { cwd: workingDirectory, maxBuffer: 20 * 1024 * 1024 });
  const checksum = crypto.createHash('sha256').update(diff, 'utf8').digest('hex');

  return {
    baseSha,
    diff,
    changedFiles,
    checksum,
    manifest: { baseSha, changes },
  };
}

async function main() {
  const controlPlaneUrl = (process.env.OTONOM_CONTROL_PLANE_URL || '').replace(/\/+$/, '');
  if (!controlPlaneUrl) {
    throw new Error('OTONOM_CONTROL_PLANE_URL is not configured.');
  }
  const bootstrapPath = path.resolve('bootstrap.json');
  if (!fs.existsSync(bootstrapPath)) {
    throw new Error('bootstrap.json not found in working directory.');
  }

  const bundle = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  const { assignmentId, sessionToken, taskId, runId, attempt, baseSha, instructions } = bundle;
  const workspaceDir = path.resolve('.otonom/target-worktree');
  fatalReportContext = {
    controlPlaneUrl,
    assignmentId,
    sessionToken,
    taskId,
    taskNodeId: bundle.taskNodeId,
    leaseId: bundle.leaseId,
    runId,
    attempt,
    secrets: { ...(bundle.secrets || {}), deployKey: bundle.source && bundle.source.privateDeployKey },
  };

  // 1. Checkout source if deploy key strategy used
  try {
    if (bundle.source && bundle.source.strategy === 'READ_ONLY_DEPLOY_KEY') {
      await performDeployKeyCheckout(
        bundle.source.cloneUrl,
        bundle.source.targetSha,
        bundle.source.privateDeployKey,
        workspaceDir,
      );
    }
  } finally {
    // 2. Immediately shred and delete bootstrap.json before OpenCode runs
    if (fs.existsSync(bootstrapPath)) {
      try {
        fs.writeFileSync(bootstrapPath, Buffer.alloc(4096, 0));
        fs.unlinkSync(bootstrapPath);
      } catch {}
    }
  }

  let isAborted = false;
  let activeProcess = null;
  const pendingInstructions = [];
  const isPosix = process.platform !== 'win32';

  function killProcessTree(proc, signal = 'SIGTERM') {
    if (!proc || !proc.pid) return;
    try {
      if (isPosix) {
        process.kill(-proc.pid, signal);
      } else {
        proc.kill(signal);
      }
    } catch {}
  }

  function abort(reason, suppressFatalReport = false) {
    if (isAborted) return;
    isAborted = true;
    if (suppressFatalReport) suppressTerminationFatalReport = true;
    console.error('[WorkerRunner] Aborting:', reason);
    if (activeProcess) {
      killProcessTree(activeProcess, 'SIGTERM');
      const procToKill = activeProcess;
      setTimeout(() => {
        killProcessTree(procToKill, 'SIGKILL');
      }, 2000).unref();
    }
  }

  // 3. Start Heartbeat Loop
  const heartbeatInterval = parseInt(process.env.OTONOM_HEARTBEAT_INTERVAL_MS || '30000', 10);
  const heartbeatTimer = setInterval(async () => {
    try {
      const res = await fetch(`${controlPlaneUrl}/api/v1/workers/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({ assignmentId }),
      });
      if (res.status === 401 || res.status === 403) {
        abort('Heartbeat rejected: session revoked or expired', true);
      }
    } catch {}
  }, heartbeatInterval);
  heartbeatTimer.unref();

  // 4. Start Commands Loop
  let lastSeq = 0;
  const commandPollInterval = parseInt(process.env.OTONOM_COMMAND_POLL_INTERVAL_MS || '5000', 10);
  const commandTimer = setInterval(async () => {
    try {
      const res = await fetch(`${controlPlaneUrl}/api/v1/workers/commands?assignmentId=${encodeURIComponent(assignmentId)}&afterSeq=${lastSeq}`, {
        headers: { Authorization: `Bearer ${sessionToken}` },
      });
      if (res.status === 401 || res.status === 403) {
        abort('Commands channel rejected: session revoked or expired', true);
        return;
      }
      if (res.ok) {
        const body = await res.json();
        const commands = Array.isArray(body) ? body : (body.commands || []);
        for (const cmd of commands) {
          if (cmd.type === 'cancel') {
            abort('Worker cancelled via control-plane command', true);
          } else if (cmd.type === 'pause' && activeProcess) {
            killProcessTree(activeProcess, 'SIGSTOP');
          } else if (cmd.type === 'resume' && activeProcess) {
            killProcessTree(activeProcess, 'SIGCONT');
          } else if (cmd.type === 'inject_instruction' && cmd.payload?.instruction) {
            pendingInstructions.push(cmd.payload.instruction);
          } else if (cmd.type === 'retry') {
            pendingInstructions.push('Retry the previous task step, inspect the current worktree, and fix remaining issues.');
          } else if (cmd.type === 'replan_required') {
            abort('Worker stopped because replanning is required', true);
          }
        }
        if (commands.length > 0) {
          const maxSeq = Math.max(...commands.map((c) => c.sequence || 0));
          if (maxSeq > lastSeq) lastSeq = maxSeq;
        }
      }
    } catch {}
  }, commandPollInterval);
  commandTimer.unref();

  // 5. Ingest WORKER_STARTED event
  try {
    await fetch(`${controlPlaneUrl}/api/v1/workers/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionToken}`,
      },
      body: JSON.stringify({
        assignmentId,
        eventId: `evt-started-${Date.now()}`,
        type: 'WORKER_STARTED',
        payload: { taskId, role: bundle.role, baseSha },
      }),
    });
  } catch {}

  // 6. Execute OpenCode directly. Provider credentials, if any, are only
  // the explicitly delegated task secrets returned by the authenticated control plane.
  const sanitizedEnv = buildSanitizedEnvironment(bundle.secrets || {});
  const safeCommandEnv = buildSanitizedEnvironment({});
  const prompt = instructions || 'Review and implement requested changes.';
  const evidence = [];
  let setupExitCode = 0;
  let setupStdout = '';
  let setupStderr = '';

  for (const command of bundle.setupCommands || []) {
    const setupStartedAt = Date.now();
    const setupResult = await new Promise((resolve) => {
      const child = spawn('/bin/sh', ['-lc', command], {
        cwd: workspaceDir,
        env: safeCommandEnv,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: isPosix,
      });
      activeProcess = child;
      let stdout = '';
      let stderr = '';
      child.stdout?.on('data', (data) => (stdout += data.toString('utf8')));
      child.stderr?.on('data', (data) => (stderr += data.toString('utf8')));
      child.once('error', (err) => {
        activeProcess = null;
        resolve({ stdout, stderr: stderr || err.message, exitCode: 1 });
      });
      child.once('close', (code) => {
        activeProcess = null;
        resolve({ stdout, stderr, exitCode: code ?? 1 });
      });
    });
    setupStdout += setupResult.stdout;
    setupStderr += setupResult.stderr;
    setupExitCode = setupResult.exitCode;
    evidence.push({
      type: 'custom',
      command,
      exitCode: setupResult.exitCode,
      durationMs: Date.now() - setupStartedAt,
      metadata: {
        stage: 'setup',
        stdoutLen: setupResult.stdout.length,
        stderrLen: setupResult.stderr.length,
      },
    });
    if (setupResult.exitCode !== 0 || isAborted) break;
  }

  async function runOpenCode(message, continueSession = false) {
    const args = ['run', '--standalone', '--format', 'json'];
    if (continueSession) args.push('--continue');
    if (bundle.modelPolicy?.preferredModel && bundle.modelPolicy.preferredModel !== 'auto') {
      args.push('--model', bundle.modelPolicy.preferredModel);
    }
    args.push(message);

    const startedAt = Date.now();
    const result = await new Promise((resolve) => {
      const child = spawn('opencode', args, {
        cwd: workspaceDir,
        env: sanitizedEnv,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: isPosix,
      });
      activeProcess = child;

      let stdout = '';
      let stderr = '';
      child.stdout?.on('data', (data) => {
        stdout += data.toString('utf8');
        if (stdout.length > 20 * 1024 * 1024) abort('OpenCode stdout exceeded safety limit');
      });
      child.stderr?.on('data', (data) => {
        stderr += data.toString('utf8');
        if (stderr.length > 20 * 1024 * 1024) abort('OpenCode stderr exceeded safety limit');
      });
      child.once('error', (err) => {
        activeProcess = null;
        resolve({ stdout, stderr: stderr || err.message, exitCode: 1 });
      });
      child.once('close', (code) => {
        activeProcess = null;
        resolve({ stdout, stderr, exitCode: code ?? 1 });
      });
    });

    evidence.push({
      type: 'custom',
      command: continueSession ? 'opencode run --standalone --continue --format json' : 'opencode run --standalone --format json',
      exitCode: result.exitCode,
      durationMs: Date.now() - startedAt,
      metadata: { stdoutLen: result.stdout.length, stderrLen: result.stderr.length },
    });
    return result;
  }

  let result;
  let stdoutCollected = setupStdout;
  let stderrCollected = setupStderr;
  let exitCode = setupExitCode;

  if (setupExitCode === 0) {
    result = await runOpenCode(prompt, false);
    stdoutCollected += result.stdout;
    stderrCollected += result.stderr;
    exitCode = result.exitCode;
  }

  while (exitCode === 0 && result && pendingInstructions.length > 0 && !isAborted) {
    const nextInstruction = pendingInstructions.shift();
    if (!nextInstruction) break;
    result = await runOpenCode(nextInstruction, true);
    stdoutCollected += result.stdout;
    stderrCollected += result.stderr;
    exitCode = result.exitCode;
  }

  if (isAborted) {
    clearInterval(heartbeatTimer);
    clearInterval(commandTimer);
    const controlAbort = new Error(
      'Worker execution aborted: authority revoked or assignment cancelled.',
    );
    controlAbort.suppressFatalReport = true;
    throw controlAbort;
  }

  // 7. Execute required repository-passport quality gates WITHOUT model
  // provider credentials. Gate commands are trusted control-plane metadata.
  if (exitCode === 0) {
    const gateEnv = buildSanitizedEnvironment({});
    const supportedTypes = new Set(['test', 'lint', 'typecheck', 'format', 'security', 'build']);
    for (const gate of bundle.qualityGates || []) {
      const commands = bundle.qualityGateCommands?.[gate] || [];
      if (commands.length === 0) {
        evidence.push({
          type: supportedTypes.has(gate) ? gate : 'custom',
          command: '<' + gate + ':not-configured>',
          exitCode: 127,
          durationMs: 0,
          metadata: { reason: 'QUALITY_GATE_COMMAND_NOT_CONFIGURED' },
        });
        exitCode = 127;
        stderrCollected += '\nRequired quality gate "' + gate + '" has no configured command.';
        break;
      }

      for (const command of commands) {
        const gateStartedAt = Date.now();
        const gateResult = await new Promise((resolve) => {
          const child = spawn('/bin/sh', ['-lc', command], {
            cwd: workspaceDir,
            env: gateEnv,
            shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
            detached: isPosix,
          });
          activeProcess = child;
          let stdout = '';
          let stderr = '';
          child.stdout?.on('data', (data) => (stdout += data.toString('utf8')));
          child.stderr?.on('data', (data) => (stderr += data.toString('utf8')));
          child.once('error', (err) => {
            activeProcess = null;
            resolve({ stdout, stderr: stderr || err.message, exitCode: 1 });
          });
          child.once('close', (code) => {
            activeProcess = null;
            resolve({ stdout, stderr, exitCode: code ?? 1 });
          });
        });
        evidence.push({
          type: supportedTypes.has(gate) ? gate : 'custom',
          command,
          exitCode: gateResult.exitCode,
          durationMs: Date.now() - gateStartedAt,
          metadata: { stdoutLen: gateResult.stdout.length, stderrLen: gateResult.stderr.length },
        });
        if (gateResult.exitCode !== 0) {
          exitCode = gateResult.exitCode;
          stderrCollected += '\nQuality gate "' + gate + '" failed: ' + (gateResult.stderr || gateResult.stdout);
          break;
        }
      }
      if (exitCode !== 0) break;
    }
  }

  // 8. Collect the final worktree after quality gates (format gates may change files).
  let patch;
  if (!isAborted && exitCode === 0) {
    patch = await collectWorktreePatch(workspaceDir, baseSha);
  }

  clearInterval(heartbeatTimer);
  clearInterval(commandTimer);

  // 9. Submit result manifest
  const submission = {
    taskId,
    taskNodeId: bundle.taskNodeId,
    assignmentId,
    sessionToken,
    runId,
    attempt,
    result: {
      status: exitCode === 0 ? 'completed' : 'failed',
      summary: exitCode === 0 ? 'OpenCode completed execution' : `OpenCode exited with code ${exitCode}`,
      error:
        exitCode === 0
          ? undefined
          : redactKnownSecrets(
              stderrCollected || stdoutCollected,
              fatalReportContext ? fatalReportContext.secrets : bundle.secrets || {},
            ),
    },
    patch,
    evidence,
  };

  const submitRes = await fetch(`${controlPlaneUrl}/api/v1/workers/submit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${sessionToken}`,
    },
    body: JSON.stringify(submission),
  });

  if (!submitRes.ok) {
    const errorText = await submitRes.text();
    throw new Error(`Failed to submit manifest to control plane: ${submitRes.status} ${errorText}`);
  }

  console.log('[WorkerRunner] Submission accepted by control plane.');
  if (exitCode !== 0) {
    process.exit(1);
  }
}

if (process.argv[1] && process.argv[1].endsWith('trusted-runner.mjs')) {
  main().catch(async (err) => {
    // Deliberately no error detail on stdout: git/network errors embed the
    // private target remote, and this log is public on the worker-market
    // repository. Intentional control aborts have already had their authority
    // revoked and must not attempt a new submission with a dead session.
    if (!err || !err.suppressFatalReport) {
      await reportFatalPrivately(err);
    }
    console.error('[WorkerRunner Fatal] Run failed; details withheld from public logs.');
    process.exit(1);
  });
}
