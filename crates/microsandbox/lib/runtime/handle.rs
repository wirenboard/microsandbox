//! Handle to a running sandbox process.
//!
//! [`ProcessHandle`] holds the PID of the sandbox process and provides
//! methods for lifecycle management (signals, wait).

use std::{path::PathBuf, process::ExitStatus};

use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use tempfile::TempDir;
use tokio::process::Child;
use tokio::task::JoinHandle;

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Handle to a running sandbox process.
pub struct ProcessHandle {
    /// PID of the sandbox process.
    pid: u32,

    /// Name of the sandbox this process manages.
    sandbox_name: String,

    /// The sandbox child process handle.
    child: Child,

    /// When true, the Drop impl will NOT send SIGTERM.
    detached: bool,

    /// Ephemeral staging directory for file mounts. Dropped when the
    /// process handle is dropped, which auto-removes all staged files.
    _file_mounts_staging: Option<TempDir>,

    /// Sandbox `--log-dir`. Used by `wait()` to append a one-line
    /// post-mortem record (`msb-exit.log`) so the exit status of the
    /// VMM is recoverable after the agent-vm process is gone. Cleared
    /// by `disarm()` — once a sandbox is detached the parent's
    /// `wait()` observes only kernel reparenting (reaps to Ok(0)
    /// instantly or hangs forever), not the actual VMM termination,
    /// so logging that observation would be actively misleading.
    log_dir: Option<PathBuf>,

    /// Stderr-tee task spawned by `runtime::spawn::spawn_sandbox`.
    /// Held here so `wait()` can drain the last chunk (otherwise a
    /// libkrun panic backtrace's tail is lost when the runtime
    /// cancels the detached task on shutdown) and so respawn after
    /// failure waits for the prior task to finish writing before
    /// truncating `msb.stderr.log` for the new boot. `take()`n inside
    /// `wait()` so it's only awaited once.
    stderr_tee: Option<JoinHandle<()>>,

    /// True once `wait()` has appended a line to `msb-exit.log` —
    /// makes that path idempotent. Without the fuse, every subsequent
    /// `wait()` call (tokio fuses `Child::wait` to return the same
    /// `ExitStatus`, and `Sandbox::wait` takes `&self` so any cloned
    /// `Sandbox` handle can call it again) would append a duplicate
    /// line with a fresh timestamp, inflating crash counts in post-
    /// mortem analysis.
    exit_logged: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProcessHandle {
    /// Create a new handle.
    pub(crate) fn new(
        pid: u32,
        sandbox_name: String,
        child: Child,
        file_mounts_staging: Option<TempDir>,
        log_dir: Option<PathBuf>,
        stderr_tee: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            pid,
            sandbox_name,
            child,
            detached: false,
            _file_mounts_staging: file_mounts_staging,
            log_dir,
            stderr_tee,
            exit_logged: false,
        }
    }

    /// Get the sandbox process PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the sandbox name.
    pub fn sandbox_name(&self) -> &str {
        &self.sandbox_name
    }

    /// Send SIGKILL to the sandbox process for immediate termination.
    pub fn kill(&self) -> MicrosandboxResult<()> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "sending SIGKILL");
        signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGKILL)?;
        Ok(())
    }

    /// Send SIGUSR1 to the sandbox process to trigger a graceful drain.
    ///
    /// The libkrun signal handler catches SIGUSR1, writes to the exit event
    /// fd, exit observers run, and the process terminates.
    pub fn drain(&self) -> MicrosandboxResult<()> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "sending SIGUSR1 (drain)");
        signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGUSR1)?;
        Ok(())
    }

    /// Wait for the sandbox process to exit.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "waiting for exit");
        let status = self.child.wait().await?;
        tracing::debug!(pid = self.pid, ?status, "process exited");

        // Drain the stderr tee task before returning so the panic
        // backtrace's last chunk is flushed to msb.stderr.log even
        // when the parent runtime is shutting down right after wait.
        // Bounded timeout (2 s) so a tee task that's wedged for some
        // unrelated reason (e.g. closed log dir on NFS) can never
        // hold wait() open.
        if let Some(tee) = self.stderr_tee.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tee).await;
        }

        let abnormal =
            !status.success() || std::os::unix::process::ExitStatusExt::signal(&status).is_some();
        if abnormal {
            tracing::warn!(
                pid = self.pid,
                sandbox = %self.sandbox_name,
                ?status,
                "msb sandbox process exited abnormally"
            );
        }
        // Persist the exit record — but only once per handle, even
        // across multiple wait() calls. tokio fuses Child::wait so a
        // second call returns the same ExitStatus successfully;
        // without the fuse, that second call would re-enter the
        // append path and duplicate the line with a fresh timestamp,
        // misrepresenting crash chronology in msb-exit.log.
        if !self.exit_logged
            && let Some(dir) = self.log_dir.as_deref()
        {
            self.exit_logged = true;
            let path = dir.join("msb-exit.log");
            let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs().to_string(),
                Err(e) => {
                    // Host clock is pre-1970 (fresh VM/container
                    // without RTC sync). The previous unwrap_or(0)
                    // silently wrote 0 for every boot, defeating
                    // the chronology the file is supposed to give.
                    // Mark explicitly so the post-mortem reader
                    // knows.
                    tracing::warn!(
                        error = %e,
                        "msb-exit.log: host clock predates UNIX_EPOCH; timestamp will be 'pre-epoch'"
                    );
                    "pre-epoch".to_string()
                }
            };
            // Sanitize the sandbox name: the file is tab-delimited
            // and we never want a stray '\t' / '\n' to shift every
            // subsequent column for a downstream parser. Replace
            // anything < 0x20 with '?'.
            let safe_name: String = self
                .sandbox_name
                .chars()
                .map(|c| if (c as u32) < 0x20 || c == '\u{7f}' { '?' } else { c })
                .collect();
            let line = format!(
                "{now}\tpid={}\tsandbox={}\tstatus={:?}\tabnormal={}\n",
                self.pid, safe_name, status, abnormal
            );
            // Append so a series of crashes is visible at a glance.
            // Best-effort: a write failure here just costs a hint.
            use tokio::io::AsyncWriteExt as _;
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                let _ = f.write_all(line.as_bytes()).await;
                let _ = f.flush().await;
            }
        }
        Ok(status)
    }

    /// Check if the process has exited without blocking.
    pub fn try_wait(&mut self) -> MicrosandboxResult<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    /// Disarm the SIGTERM safety net so the sandbox keeps running after
    /// this handle is dropped. Used by detached sandbox flows.
    ///
    /// Also prevents the file-mounts staging directory from being deleted,
    /// since the detached VM process still reads from it via virtiofs.
    pub fn disarm(&mut self) {
        self.detached = true;

        // Consume the TempDir without deleting its contents — the detached
        // VM process still reads from it via virtiofs.
        if let Some(td) = self._file_mounts_staging.take() {
            let _ = td.keep();
        }
        // Clear log_dir so wait() can't write a misleading exit
        // record. After disarm the child is reparented to init on
        // agent-vm exit; the parent's eventual wait() would observe
        // either an instant Ok(0) (already reaped by init) or hang
        // forever — neither reflects the actual VMM termination
        // state, so logging it is actively misleading.
        self.log_dir = None;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // Abort any still-running stderr tee task. Without this, the
        // task can outlive the ProcessHandle on a respawn-after-
        // failure path and race the next boot's truncate(true) open
        // of msb.stderr.log.
        if let Some(tee) = self.stderr_tee.take() {
            tee.abort();
        }

        if self.detached {
            return;
        }

        // Safety net: send SIGTERM so the sandbox process is cleaned up
        // if the handle is dropped without an explicit stop.
        if let Ok(None) = self.child.try_wait()
            && let Some(pid) = self.child.id()
        {
            tracing::debug!(pid, sandbox = %self.sandbox_name, "drop: sending SIGTERM safety net");
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
    }
}
