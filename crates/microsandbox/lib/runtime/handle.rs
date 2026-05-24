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
    /// VMM is recoverable after the agent-vm process is gone.
    log_dir: Option<PathBuf>,
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
    ) -> Self {
        Self {
            pid,
            sandbox_name,
            child,
            detached: false,
            _file_mounts_staging: file_mounts_staging,
            log_dir,
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
        // Persist exit record so post-mortem can answer "did the VMM
        // crash?" even after agent-vm itself is gone. Non-zero / signal
        // exits also rate a `warn` trace so they appear under default
        // `RUST_LOG=warn`.
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
        if let Some(dir) = self.log_dir.as_deref() {
            let path = dir.join("msb-exit.log");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let line = format!(
                "{now}\tpid={}\tsandbox={}\tstatus={:?}\tabnormal={}\n",
                self.pid, self.sandbox_name, status, abnormal
            );
            // Append so a series of crashes is visible at a glance —
            // "5 boots in a row all SIGKILL'd at ~3h uptime" is much
            // more useful than just the last boot's record. Best-
            // effort: a write failure here just costs a hint.
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
    /// since the detached VM process still needs the backing files.
    pub fn disarm(&mut self) {
        self.detached = true;

        // Consume the TempDir without deleting its contents — the detached
        // VM process still reads from it via virtiofs.
        if let Some(td) = self._file_mounts_staging.take() {
            let _ = td.keep();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ProcessHandle {
    fn drop(&mut self) {
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
