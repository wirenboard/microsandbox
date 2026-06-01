//! Sandbox process entry point and VM configuration.
//!
//! The [`enter()`] function starts background services (agent relay,
//! heartbeat, idle timeout), configures the VMM, and hands control to
//! `Vm::enter()` from msb_krun. It **never returns** — the VMM calls
//! `_exit()` on guest shutdown after running exit observers.

use std::io::Write;
use std::num::NonZero;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::run as run_entity;
use microsandbox_filesystem::{DynFileSystem, PassthroughConfig, PassthroughFs};
use msb_krun::VmBuilder;
use sea_orm::{ColumnTrait, EntityTrait, Set};
use serde::Serialize;

use crate::console::{AgentConsoleBackend, ConsoleSharedState};
use crate::heartbeat::HeartbeatReader;
use crate::logging::LogLevel;
use crate::metrics::run_metrics_sampler;
use crate::relay::AgentRelay;
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Exit reason tags stored in the shared `AtomicU8`.
const EXIT_REASON_COMPLETED: u8 = 0;
const EXIT_REASON_IDLE_TIMEOUT: u8 = 1;
const EXIT_REASON_MAX_DURATION: u8 = 2;
const EXIT_REASON_SIGNAL: u8 = 3;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Full configuration for the sandbox process.
///
/// Combines VM hardware settings with sandbox-level metadata (name, DB,
/// agent relay, lifecycle policies). Passed to [`enter()`].
#[derive(Debug)]
pub struct Config {
    /// Name of the sandbox.
    pub sandbox_name: String,

    /// Database ID of the sandbox row.
    pub sandbox_id: i32,

    /// Selected tracing verbosity.
    pub log_level: Option<LogLevel>,

    /// Path to the sandbox database file.
    pub sandbox_db_path: PathBuf,

    /// Timeout when acquiring a sandbox database connection from the pool.
    pub sandbox_db_connect_timeout_secs: u64,

    /// Directory for log files.
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    pub runtime_dir: PathBuf,

    /// Path to the Unix domain socket for the agent relay.
    pub agent_sock_path: PathBuf,

    /// Whether to forward VM console output to stdout.
    pub forward_output: bool,

    /// Idle timeout in seconds (None = no idle timeout).
    pub idle_timeout_secs: Option<u64>,

    /// Maximum sandbox lifetime in seconds (None = no limit).
    pub max_duration_secs: Option<u64>,

    /// Metrics sampling interval in milliseconds; `None` disables sampling.
    pub metrics_sample_interval_ms: Option<NonZero<u64>>,

    /// VM hardware and rootfs configuration.
    pub vm: VmConfig,
}

/// Specification for the writable upper layer attached as virtio-blk.
///
/// Today the upper is always a flat raw ext4 file, so `format = Raw`
/// and `backing` is empty. The shape is forward-compatible with
/// qcow2 backing chains: when chains land, `format = Qcow2` and
/// `backing` lists ancestor files that the VMM must also map. The
/// runtime walks `backing` and attaches each as a read-only disk.
#[derive(Debug, Clone)]
pub struct UpperSpec {
    /// Path to the head upper file. Mounted writable.
    pub primary: PathBuf,
    /// On-disk format. `Raw` today; `Qcow2` once chains land.
    pub format: msb_krun::DiskImageFormat,
    /// Ancestor files in the backing chain, oldest-first. Empty today.
    pub backing: Vec<PathBuf>,
    /// Whether the head file is read-only. Should be `false` for the
    /// running sandbox's upper.
    pub read_only: bool,
}

/// Specification for a disk-image volume mount attached to the guest.
///
/// Each entry becomes one extra virtio-blk device. Agentd consumes the
/// companion `MSB_DISK_MOUNTS` env var to know which device to mount where.
#[derive(Debug, Clone)]
pub struct DiskMountSpec {
    /// Stable block id. Surfaced in the guest as the virtio-blk `serial`
    /// so agentd can resolve it via `/dev/disk/by-id/virtio-<id>`.
    pub id: String,

    /// Host path to the disk image file.
    pub host: PathBuf,

    /// Guest mount path. Not needed by the VMM, but carried here for
    /// logging/validation; agentd reads the canonical value from the env.
    pub guest: String,

    /// Disk image format.
    pub format: msb_krun::DiskImageFormat,

    /// Inner filesystem type, if specified; otherwise agentd probes.
    pub fstype: Option<String>,

    /// Whether the mount is read-only.
    pub readonly: bool,
}

/// VM hardware and rootfs configuration.
pub struct VmConfig {
    /// Path to the libkrunfw shared library.
    pub libkrunfw_path: PathBuf,

    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// Memory in MiB.
    pub memory_mib: u32,

    /// Root filesystem path for direct passthrough mounts.
    pub rootfs_path: Option<PathBuf>,

    /// Disk image path for virtio-blk rootfs (single disk, legacy).
    pub rootfs_disk: Option<PathBuf>,

    /// Disk image format string ("qcow2", "raw", "vmdk").
    pub rootfs_disk_format: Option<String>,

    /// Whether the disk image is read-only.
    pub rootfs_disk_readonly: bool,

    /// VMDK descriptor path for EROFS fsmerge OCI rootfs (read-only).
    pub rootfs_vmdk: Option<PathBuf>,

    /// Upper ext4 disk path for writable overlay (paired with rootfs_vmdk).
    ///
    /// Convenience field equivalent to `rootfs_upper_spec` with format
    /// `Raw` and no backing chain. When `rootfs_upper_spec` is set, it
    /// takes precedence; this field is the fast path for the common case.
    pub rootfs_upper: Option<PathBuf>,

    /// Full spec for the writable upper layer.
    ///
    /// Forward-compat seam for qcow2 backing chains. Today this always
    /// produces `Raw` with an empty backing chain — equivalent to
    /// `rootfs_upper`. The qcow2 future populates `format = Qcow2`
    /// and a non-empty `backing` chain without touching every call
    /// site.
    pub rootfs_upper_spec: Option<UpperSpec>,

    /// Additional mounts as `tag:host_path[:ro]` strings.
    pub mounts: Vec<String>,

    /// Disk-image volume mounts attached as extra virtio-blk devices.
    pub disks: Vec<DiskMountSpec>,

    /// Pre-built filesystem backends as `(tag, backend)` pairs.
    pub backends: Vec<(String, Box<dyn DynFileSystem + Send + Sync>)>,

    /// Path to the init binary in the guest.
    pub init_path: Option<PathBuf>,

    /// Environment variables as `KEY=VALUE` pairs.
    pub env: Vec<String>,

    /// Working directory inside the guest.
    pub workdir: Option<PathBuf>,

    /// Path to the executable to run in the guest.
    pub exec_path: Option<PathBuf>,

    /// Arguments to the executable.
    pub exec_args: Vec<String>,

    /// Network configuration for the smoltcp in-process stack.
    #[cfg(feature = "net")]
    pub network: microsandbox_network::config::NetworkConfig,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    pub sandbox_slot: u64,
}

/// JSON structure written to stdout on startup.
#[derive(Debug, Serialize)]
struct StartupInfo {
    pid: u32,
}

#[cfg(feature = "net")]
type NetworkTerminationHandle = microsandbox_network::network::TerminationHandle;

#[cfg(not(feature = "net"))]
type NetworkTerminationHandle = ();

#[cfg(feature = "net")]
type NetworkMetricsHandle = microsandbox_network::network::MetricsHandle;

#[cfg(not(feature = "net"))]
type NetworkMetricsHandle = ();

/// Bundle of handles needed to spawn the auto-publish task after the
/// relay is ready: the port-command sender (drives `PortPublisher`
/// add/remove) and the auto-publish config (poll interval, host bind).
/// Captured during `build_vm` so the caller can wire them up once
/// the agent socket exists.
///
/// Defined unconditionally as a unit-like type when the `net`
/// feature is off so it can sit in `build_vm`'s return tuple
/// without per-field `cfg`-on-tuple-field tricks (which the
/// language doesn't allow).
#[cfg(feature = "net")]
pub(crate) struct AutoPublishHandles {
    pub(crate) port_handle:
        tokio::sync::mpsc::UnboundedSender<microsandbox_network::publisher::PortCommand>,
    pub(crate) cfg: microsandbox_network::config::AutoPublishConfig,
    /// Guest's VLAN IPv4 address. Passed to agentd in
    /// `LoopbackForwardReq` so it knows what address to bind the
    /// in-guest forwarder on for `127.0.0.1`-only services.
    /// `None` when the sandbox runs v6-only.
    pub(crate) guest_ipv4: Option<std::net::Ipv4Addr>,
    /// Guest's VLAN IPv6 address. Passed to agentd in
    /// `LoopbackForwardReq` so it can bind on the v6 NIC address
    /// for `[::1]`-only services. `None` when the sandbox runs
    /// v4-only.
    pub(crate) guest_ipv6: Option<std::net::Ipv6Addr>,
}

#[cfg(not(feature = "net"))]
pub(crate) struct AutoPublishHandles;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for VmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmConfig")
            .field("libkrunfw_path", &self.libkrunfw_path)
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("rootfs_path", &self.rootfs_path)
            .field("rootfs_vmdk", &self.rootfs_vmdk)
            .field("rootfs_upper", &self.rootfs_upper)
            .field("rootfs_upper_spec", &self.rootfs_upper_spec)
            .field("rootfs_disk", &self.rootfs_disk)
            .field("rootfs_disk_format", &self.rootfs_disk_format)
            .field("rootfs_disk_readonly", &self.rootfs_disk_readonly)
            .field("mounts", &self.mounts)
            .field("disks", &self.disks)
            .field("backends", &format!("[{} backend(s)]", self.backends.len()))
            .field("init_path", &self.init_path)
            .field("env", &self.env)
            .field("workdir", &self.workdir)
            .field("exec_path", &self.exec_path)
            .field("exec_args", &self.exec_args)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Enter the sandbox process.
///
/// This function **never returns**. It starts background services (agent
/// relay, heartbeat, idle timeout), configures the VMM, writes a startup
/// JSON to stdout, and calls `Vm::enter()` which takes over the process.
pub fn enter(config: Config) -> ! {
    // Capture log_dir before moving config into run() — we need it after
    // a failure to write boot-error.json, regardless of how far run() got.
    let log_dir = config.log_dir.clone();
    let result = run(config);
    match result {
        Ok(infallible) => match infallible {},
        Err(e) => {
            // Write the structured boot-error record so the parent CLI
            // can surface a real cause inline. Best-effort: any failure
            // to write falls back to the existing eprintln path, which
            // is already captured into runtime.log via setup_log_capture.
            let boot_err = crate::boot_error::BootError::from_runtime_error(&e);
            if let Err(write_err) = boot_err.write_atomic(&log_dir) {
                eprintln!("failed to write boot-error.json: {write_err}");
            }
            eprintln!("sandbox error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(config: Config) -> RuntimeResult<std::convert::Infallible> {
    // Write startup JSON and redirect output FIRST, before any tracing.
    // This ensures all tracing goes to runtime.log, not the terminal.
    let pid = std::process::id();
    let startup = StartupInfo { pid };
    let startup_json = serde_json::to_string(&startup)
        .map_err(|e| RuntimeError::Custom(format!("serialize startup: {e}")))?;

    write_startup_info(&startup_json)?;
    setup_log_capture(&config.log_dir, config.forward_output)?;

    tracing::info!(sandbox = %config.sandbox_name, "sandbox starting");

    // Create console shared state (ring buffers + wake pipes).
    let shared = Arc::new(ConsoleSharedState::new());
    let console_backend = AgentConsoleBackend::new(Arc::clone(&shared));

    // Build tokio runtime for relay, heartbeat, and timer tasks.
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| RuntimeError::Custom(format!("tokio runtime: {e}")))?;

    // Set up runtime directory.
    std::fs::create_dir_all(&config.runtime_dir)?;
    std::fs::create_dir_all(config.runtime_dir.join("scripts"))?;

    // Create the relay and persist the run record with a single runtime hop.
    let (mut relay, db, run_db_id) = tokio_rt.block_on(async {
        let relay = AgentRelay::new(&config.agent_sock_path, Arc::clone(&shared));
        let db = connect_db(
            &config.sandbox_db_path,
            config.sandbox_db_connect_timeout_secs,
        );
        let (relay, db) = tokio::try_join!(relay, db)?;
        let run_db_id = insert_run(&db, config.sandbox_id, pid).await?;
        Ok::<_, RuntimeError>((relay, db, run_db_id))
    })?;

    // Attach the exec.log writer so the ring reader can capture the
    // primary session's stdout/stderr. Failure to open the file is
    // non-fatal — log capture is best-effort and must not block boot.
    let exec_log_writer: Option<Arc<crate::exec_log::LogWriter>> =
        match crate::exec_log::LogWriter::open(&config.log_dir) {
            Ok(writer) => {
                let arc = Arc::new(writer);
                relay = relay.with_log_writer(Arc::clone(&arc));
                Some(arc)
            }
            Err(err) => {
                tracing::warn!(error = %err, "exec_log: open failed, capture disabled");
                None
            }
        };

    // Shared termination reason — background tasks store the reason before
    // triggering exit; the exit observer reads it for the DB update.
    let exit_reason: Arc<std::sync::atomic::AtomicU8> =
        Arc::new(std::sync::atomic::AtomicU8::new(EXIT_REASON_COMPLETED));

    // Build the VM with an exit observer for DB cleanup and socket removal.
    // The on_exit closure runs synchronously on the VMM thread before _exit().
    let rt_handle = tokio_rt.handle().clone();
    let exit_db = db.clone();
    let exit_sandbox_id = config.sandbox_id;
    let exit_run_id = run_db_id;
    let exit_reason_for_observer = Arc::clone(&exit_reason);
    let exit_sock_path = config.agent_sock_path.clone();
    let exit_log_writer = exec_log_writer.clone();
    let (
        vm,
        _network_termination_handle,
        network_metrics_handle,
        auto_publish_handles,
    ) = match build_vm(
        &config,
        console_backend,
        move |exit_code: i32| {
            use microsandbox_db::entity::sandbox as sandbox_entity;
            use sea_orm::QueryFilter;
            use sea_orm::sea_query::Expr;

            // Map (exit_code, reason tag) → TerminationReason.
            let reason_tag = exit_reason_for_observer.load(std::sync::atomic::Ordering::SeqCst);
            let reason = match reason_tag {
                EXIT_REASON_IDLE_TIMEOUT => run_entity::TerminationReason::IdleTimeout,
                EXIT_REASON_MAX_DURATION => run_entity::TerminationReason::MaxDurationExceeded,
                EXIT_REASON_SIGNAL => run_entity::TerminationReason::Signal,
                _ if exit_code == 0 => run_entity::TerminationReason::Completed,
                _ => run_entity::TerminationReason::Failed,
            };

            rt_handle.block_on(async {
                let now = chrono::Utc::now().naive_utc();

                // Mark run as terminated with exit code and reason.
                let _ = run_entity::Entity::update_many()
                    .col_expr(
                        run_entity::Column::Status,
                        Expr::value(run_entity::RunStatus::Terminated),
                    )
                    .col_expr(run_entity::Column::TerminationReason, Expr::value(reason))
                    .col_expr(run_entity::Column::ExitCode, Expr::value(exit_code))
                    .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
                    .filter(run_entity::Column::Id.eq(exit_run_id))
                    .exec(&exit_db)
                    .await;

                // Mark sandbox as stopped.
                let _ = sandbox_entity::Entity::update_many()
                    .col_expr(
                        sandbox_entity::Column::Status,
                        Expr::value(sandbox_entity::SandboxStatus::Stopped),
                    )
                    .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
                    .filter(sandbox_entity::Column::Id.eq(exit_sandbox_id))
                    .exec(&exit_db)
                    .await;
            });

            // Inject the exec.log lifecycle-stop marker before _exit().
            // The relay's async run() loop won't get a chance to write
            // it because _exit() bypasses task cleanup.
            if let Some(ref writer) = exit_log_writer {
                writer.write_system("--- sandbox stopped ---");
            }

            // Clean up agent.sock — the relay's async cleanup won't run because
            // _exit() is called immediately after this observer returns.
            let _ = std::fs::remove_file(&exit_sock_path);
        },
        tokio_rt.handle().clone(),
    ) {
        Ok(vm) => vm,
        Err(e) => {
            let _ = tokio_rt.block_on(mark_run_failed(&db, run_db_id));
            return Err(e);
        }
    };
    let exit_handle = vm.exit_handle();

    #[cfg(feature = "net")]
    if let Some(network_termination_handle) = _network_termination_handle {
        let network_exit_handle = exit_handle.clone();
        let network_reason = Arc::clone(&exit_reason);
        network_termination_handle.set_hook(Arc::new(move || {
            tracing::warn!("secret violation requested sandbox termination");
            network_reason.store(EXIT_REASON_SIGNAL, std::sync::atomic::Ordering::SeqCst);
            network_exit_handle.trigger();
        }));
    }

    match config.metrics_sample_interval_ms {
        None => tracing::debug!(
            sandbox = %config.sandbox_name,
            "metrics sampling disabled; not spawning sampler"
        ),
        Some(interval_ms) => {
            tracing::debug!(
                sandbox = %config.sandbox_name,
                interval_ms = interval_ms.get(),
                "starting metrics sampler"
            );
            tokio_rt.spawn(run_metrics_sampler(
                db.clone(),
                config.sandbox_id,
                pid,
                interval_ms,
                network_metrics_handle
                    .map(|handle| Box::new(handle) as Box<dyn crate::metrics::NetworkMetrics>),
            ));
        }
    }

    // Spawn background tasks.
    let (_relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::watch::channel(false);
    let (relay_drain_tx, mut relay_drain_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Grab the broadcast handle off the relay BEFORE it gets moved
    // into the wait_ready/run task — `broadcast_handle()` keeps an
    // Arc to the clients map, so the handle stays valid for the
    // relay's whole lifetime.
    #[cfg(feature = "net")]
    let relay_broadcast = relay.broadcast_handle();

    // Relay: spawn a blocking task for wait_ready, then run the accept loop.
    // wait_ready() must run AFTER enter() starts the VM (agentd sends core.ready),
    // so it runs on a background thread, not blocking the main thread.
    tokio_rt.spawn(async move {
        let ready_result =
            tokio::task::spawn_blocking(move || relay.wait_ready().map(|()| relay)).await;

        match ready_result {
            Ok(Ok(relay)) => {
                if let Err(e) = relay.run(relay_shutdown_rx, relay_drain_tx).await {
                    tracing::error!("agent relay error: {e}");
                }
            }
            Ok(Err(e)) => tracing::error!("agent relay wait_ready failed: {e}"),
            Err(e) => tracing::error!("agent relay wait_ready task panicked: {e}"),
        }
    });

    // Auto-publish: spawn the poll loop now that the relay is
    // running. The loop opens a loopback UDS to agent.sock, so it's
    // safe to spawn even before wait_ready completes — the loop's
    // initial `connect_with_retry` handles the brief race.
    #[cfg(feature = "net")]
    if let Some(handles) = auto_publish_handles {
        struct RelayBroadcastAdapter(crate::relay::RelayBroadcast);
        impl crate::auto_publish::EventBroadcast for RelayBroadcastAdapter {
            fn broadcast_port_event(
                &self,
                event: microsandbox_protocol::network::PortEvent,
            ) {
                let id = microsandbox_protocol::network::PORT_EVENT_BROADCAST_ID;
                let msg = match microsandbox_protocol::message::Message::with_payload(
                    microsandbox_protocol::message::MessageType::PortEvent,
                    id,
                    &event,
                ) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                self.0.broadcast(&msg);
            }
        }
        let adapter: std::sync::Arc<dyn crate::auto_publish::EventBroadcast> =
            std::sync::Arc::new(RelayBroadcastAdapter(relay_broadcast.clone()));
        crate::auto_publish::spawn(
            tokio_rt.handle(),
            config.agent_sock_path.clone(),
            handles.cfg,
            handles.port_handle,
            handles.guest_ipv4,
            handles.guest_ipv6,
            adapter,
        );
    }

    // Shutdown listener: when the relay receives core.shutdown from an SDK
    // client (e.g. sandbox.stop()), trigger VM exit.
    {
        let shutdown_exit_handle = exit_handle.clone();
        tokio_rt.spawn(async move {
            if relay_drain_rx.recv().await.is_some() {
                tracing::info!("core.shutdown received, triggering exit");
                shutdown_exit_handle.trigger();
            }
        });
    }

    // Heartbeat/idle timeout monitor.
    if let Some(idle_secs) = config.idle_timeout_secs {
        let heartbeat_reader = HeartbeatReader::new(&config.runtime_dir);
        let idle_exit_handle = exit_handle.clone();
        let idle_reason = Arc::clone(&exit_reason);
        tokio_rt.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if heartbeat_reader.is_idle(idle_secs) {
                    tracing::info!("sandbox idle for {idle_secs}s, triggering exit");
                    idle_reason.store(
                        EXIT_REASON_IDLE_TIMEOUT,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    idle_exit_handle.trigger();
                    break;
                }
            }
        });
    }

    // Max duration timer.
    if let Some(max_secs) = config.max_duration_secs {
        let max_exit_handle = exit_handle.clone();
        let max_reason = Arc::clone(&exit_reason);
        tokio_rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(max_secs)).await;
            tracing::info!("max duration {max_secs}s exceeded, triggering exit");
            max_reason.store(
                EXIT_REASON_MAX_DURATION,
                std::sync::atomic::Ordering::SeqCst,
            );
            max_exit_handle.trigger();
        });
    }

    // Forget the tokio runtime (keep background tasks alive).
    std::mem::forget(tokio_rt);

    // Enter the VM (never returns).
    tracing::info!(sandbox = %config.sandbox_name, "entering VM");
    vm.enter()
        .map_err(|e| RuntimeError::Custom(format!("VM enter: {e}")))
}

//--------------------------------------------------------------------------------------------------
// Functions: VM Builder
//--------------------------------------------------------------------------------------------------

/// Build the `Vm` from config with an exit observer for cleanup.
fn build_vm(
    config: &Config,
    console_backend: AgentConsoleBackend,
    on_exit: impl Fn(i32) + Send + 'static,
    tokio_handle: tokio::runtime::Handle,
) -> RuntimeResult<(
    msb_krun::Vm,
    Option<NetworkTerminationHandle>,
    Option<NetworkMetricsHandle>,
    Option<AutoPublishHandles>,
)> {
    let mut exec_env = config.vm.env.clone();
    let vm = &config.vm;

    // Enable msb_krun's userspace split irqchip on x86_64. The default
    // in-kernel IOAPIC is capped by KVM at 24 pins; the VMM only hands
    // out IRQs 5..=15 from that range (arch::IRQ_MAX = 15), leaving
    // room for ~11 virtio-mmio devices total. Between the OCI rootfs
    // (one virtio-fs trampoline + two virtio-blk for VMDK lower + ext4
    // upper, plus an extra virtio-blk per qcow2 backing entry), one
    // virtio-fs per bind mount, virtio-net, virtio-vsock,
    // virtio-console, and friends, that's saturated by an unsurprising
    // config — adding an extra `--mount` then trips
    // `RegisterNetDevice(IrqsExhausted)` at boot. The userspace IOAPIC
    // raises the allocator cap to arch::IRQ_MAX_SPLIT = 223, at the
    // cost of one extra worker thread (msb_krun spawns it
    // automatically when `split_irqchip` is set). No effect on
    // aarch64 / riscv64, where the GIC/AIA already supports >200 IRQs
    // and `split_irqchip` is ignored.
    //
    // Requires msb_krun >= 0.1.13. 0.1.12's userspace IOAPIC had two
    // observable problems with split_irqchip enabled:
    //   - IRR was a `u32` (msb_krun_devices-0.1.12 legacy/ioapic.rs:98),
    //     so any IRQ delivered on pin >= 32 was silently dropped via
    //     `1 << i` wrapping. 0.1.13 widens IRR to `[u64; 4]`.
    //   - Reads/writes of the redirection table used unchecked
    //     `ioregsel - IOAPIC_REG_REDTBL_BASE` subtraction; the write
    //     path had an early `return` guard but the read path returned
    //     0 on every register the spec leaves unspecified. 0.1.13
    //     replaces both with `checked_sub`.
    // Empirically, 0.1.12 + split_irqchip + a couple of extra `--mount`
    // entries exited cleanly within ~1.3s of `entering VM` with no
    // visible panic — guest kernel almost certainly mis-read RTE state
    // via the unchecked read path and gave up. 0.1.13 boots the same
    // config to a working shell. The bumped cap was verified end-to-end
    // with 8 user `--mount` entries: 19 virtio devices brought up on
    // IO-APIC pins 5..23, well past the historic IRQ_MAX = 15 ceiling.
    // (The userspace IOAPIC's pins 24..223 are exercised by the
    // allocator but the in-guest IRQ traffic in that test all lands on
    // pins <= 23; pin-24+ RTE handling is currently covered by upstream
    // tests in msb_krun_devices, not this verification.)
    let mut builder = VmBuilder::new()
        .machine(|m| {
            m.vcpus(vm.vcpus)
                .memory_mib(vm.memory_mib as usize)
                .split_irqchip(true)
        })
        .kernel(|k| {
            let k = k.krunfw_path(&vm.libkrunfw_path);
            if let Some(ref init_path) = vm.init_path {
                k.init_path(init_path)
            } else {
                k
            }
        });

    // Root filesystem.
    if let Some(ref rootfs_path) = vm.rootfs_path {
        let cfg = PassthroughConfig {
            root_dir: rootfs_path.clone(),
            ..Default::default()
        };
        let backend =
            PassthroughFs::new(cfg).map_err(|e| RuntimeError::Custom(format!("rootfs: {e}")))?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
    } else if let Some(ref vmdk_path) = vm.rootfs_vmdk {
        // EROFS fsmerge OCI rootfs: VMDK (read-only) + upper.ext4 (writable).
        let empty_trampoline = tempfile::tempdir()?;
        let cfg = PassthroughConfig {
            root_dir: empty_trampoline.path().to_path_buf(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("trampoline rootfs: {e}")))?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));

        // Attach VMDK as read-only VMDK-format block device.
        let vmdk = vmdk_path.clone();
        builder = builder.disk(move |d| {
            d.path(&vmdk)
                .format(msb_krun::DiskImageFormat::Vmdk)
                .read_only(true)
        });

        // Attach the writable upper. Prefer the typed `UpperSpec` if
        // provided; otherwise fall back to the legacy raw-only field.
        // When chains are populated (qcow2 future), each ancestor is
        // attached read-only ahead of the head file.
        if let Some(ref spec) = vm.rootfs_upper_spec {
            for backing in spec.backing.clone() {
                builder = builder.disk(move |d| {
                    d.path(&backing)
                        .format(msb_krun::DiskImageFormat::Qcow2)
                        .read_only(true)
                });
            }
            let primary = spec.primary.clone();
            let format = spec.format;
            let read_only = spec.read_only;
            builder = builder.disk(move |d| d.path(&primary).format(format).read_only(read_only));
        } else if let Some(ref upper) = vm.rootfs_upper {
            let upper = upper.clone();
            builder = builder.disk(move |d| {
                d.path(&upper)
                    .format(msb_krun::DiskImageFormat::Raw)
                    .read_only(false)
            });
        }

        // MSB_BLOCK_ROOT env var is set by the caller (spawn_sandbox).
        let _ = empty_trampoline.keep();
    } else if let Some(ref disk_path) = vm.rootfs_disk {
        let empty_trampoline = tempfile::tempdir()?;
        let cfg = PassthroughConfig {
            root_dir: empty_trampoline.path().to_path_buf(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("trampoline rootfs: {e}")))?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));

        let format = validate_disk_format(vm.rootfs_disk_format.as_deref())
            .map_err(|e| RuntimeError::Custom(format!("disk format: {e}")))?;
        let disk_path = disk_path.clone();
        let readonly = vm.rootfs_disk_readonly;
        builder = builder.disk(move |d| d.path(&disk_path).format(format).read_only(readonly));
        append_block_root_env(&mut exec_env);

        let _ = empty_trampoline.keep();
    }

    // Runtime directory mount — agentd mounts this at /.msb for scripts
    // and heartbeat.
    {
        let runtime_tag = microsandbox_protocol::RUNTIME_FS_TAG.to_string();
        let cfg = PassthroughConfig {
            root_dir: config.runtime_dir.clone(),
            inject_init: false,
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)
            .map_err(|e| RuntimeError::Custom(format!("runtime mount: {e}")))?;
        builder = builder.fs(move |fs| fs.tag(&runtime_tag).custom(Box::new(backend)));
    }

    // Additional mounts.
    for mount_spec in &vm.mounts {
        let (spec, _readonly) = match mount_spec.strip_suffix(":ro") {
            Some(s) => (s, true),
            None => (mount_spec.as_str(), false),
        };

        if let Some((tag, path)) = spec.split_once(':') {
            let tag = tag.to_string();
            let cfg = PassthroughConfig {
                root_dir: PathBuf::from(path),
                inject_init: false,
                ..Default::default()
            };
            let backend = PassthroughFs::new(cfg)
                .map_err(|e| RuntimeError::Custom(format!("mount {tag}: {e}")))?;
            builder = builder.fs(move |fs| fs.tag(&tag).custom(Box::new(backend)));
        }
    }

    // Disk-image volume mounts. Each adds an extra virtio-blk device with
    // a stable block id so agentd can find it via /dev/disk/by-id/virtio-<id>.
    for disk in &vm.disks {
        if !disk.host.exists() {
            return Err(RuntimeError::Custom(format!(
                "disk {}: host path not found: {}",
                disk.id,
                disk.host.display()
            )));
        }
        tracing::debug!(
            id = %disk.id,
            guest = %disk.guest,
            host = %disk.host.display(),
            ?disk.format,
            fstype = ?disk.fstype,
            readonly = disk.readonly,
            "attaching disk-image volume",
        );
        let id = disk.id.clone();
        let host = disk.host.clone();
        let format = disk.format;
        let readonly = disk.readonly;
        builder = builder.disk(move |d| {
            let mut d = d.id(&id).path(&host).format(format).read_only(readonly);
            if readonly {
                // Read-only images can skip host-side sync entirely.
                d = d
                    .cache(msb_krun::CacheMode::Unsafe)
                    .sync(msb_krun::SyncMode::None);
            }
            d
        });
    }

    let mut network_termination_handle = None;
    let mut network_metrics_handle = None;
    #[cfg(feature = "net")]
    let mut auto_publish_handles: Option<AutoPublishHandles> = None;

    // Network.
    #[cfg(feature = "net")]
    if vm.network.enabled {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut network =
            microsandbox_network::network::SmoltcpNetwork::new(vm.network.clone(), vm.sandbox_slot);
        network_termination_handle = Some(network.termination_handle());
        network_metrics_handle = Some(network.metrics_handle());

        // Capture handles for auto-publish before `network` is moved
        // into the rest of the builder steps. The port_handle is
        // cloneable but the underlying sender lives until *some*
        // clone exists, so as long as we hold one the channel into
        // the smoltcp poll thread stays open.
        if let Some(ap_cfg) = vm.network.auto_publish.clone() {
            auto_publish_handles = Some(AutoPublishHandles {
                port_handle: network.port_handle(),
                cfg: ap_cfg,
                guest_ipv4: network.guest_ipv4(),
                guest_ipv6: network.guest_ipv6(),
            });
        }

        network.start(tokio_handle.clone());

        let guest_mac = network.guest_mac();
        let net_backend = network.take_backend();

        {
            let tls_dir = config.runtime_dir.join("tls");
            let _ = std::fs::create_dir_all(&tls_dir);
            if let Some(ca_pem) = network.ca_cert_pem() {
                let _ = std::fs::write(tls_dir.join("ca.pem"), &ca_pem);
            }
            if let Some(host_cas_pem) = network.host_cas_cert_pem() {
                let _ = std::fs::write(tls_dir.join("host-cas.pem"), &host_cas_pem);
            }
        }

        for (key, value) in network.guest_env_vars() {
            exec_env.push(format!("{key}={value}"));
        }

        builder = builder.net(move |n| n.mac(guest_mac).custom(net_backend));
    }

    // Execution configuration.
    prepend_scripts_path(&mut exec_env);
    // Path-bearing mount specs carry absolute guest paths that may be
    // non-ASCII (e.g. a Cyrillic project dir) or contain whitespace.
    // libkrun packs all guest env into the kernel command line, which it
    // validates as printable-ASCII-only and `.unwrap()`s — a stray byte
    // panics the VMM before boot. Route those vars through the runtime
    // virtiofs share (read by agentd during init) instead of the cmdline.
    relocate_path_bearing_env(&config.runtime_dir, &mut exec_env)?;
    builder = builder.exec(|mut e| {
        if let Some(ref path) = vm.exec_path {
            e = e.path(path);
        }
        if !vm.exec_args.is_empty() {
            e = e.args(&vm.exec_args);
        }
        for env_str in &exec_env {
            if let Some((key, value)) = env_str.split_once('=') {
                e = e.env(key, value);
            }
        }
        if let Some(ref workdir) = vm.workdir {
            e = e.workdir(workdir);
        }
        e
    });

    // Console — ring-buffer-based custom backend for agent protocol, plus
    // implicit console output routed to kernel.log for kernel/init logs.
    // NOTE: The implicit console must remain enabled (do not call
    // `disable_implicit()`) because disk image rootfs boots depend on it.
    let kernel_log_path = config.log_dir.join("kernel.log");
    builder = builder.console(|c| {
        c.output(&kernel_log_path).custom(
            microsandbox_protocol::AGENT_PORT_NAME,
            Box::new(console_backend),
        )
    });

    // Exit observer — runs synchronously before _exit() for DB cleanup.
    builder = builder.on_exit(on_exit);

    let vm = builder
        .build()
        .map_err(|e| RuntimeError::Custom(format!("build VM: {e}")))?;

    #[cfg(not(feature = "net"))]
    let auto_publish_handles: Option<AutoPublishHandles> = None;
    Ok((
        vm,
        network_termination_handle,
        network_metrics_handle,
        auto_publish_handles,
    ))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Set up host log capture.
///
/// Redirects stderr through a pipe so a background thread can write to a
/// rotating log file (`runtime.log`). Stdout is redirected to `/dev/null`
/// because kernel console output is routed to `kernel.log` directly via
/// `console_output` in the VM builder.
///
/// If `forward` is true, stderr is also tee'd to the original fd.
fn setup_log_capture(log_dir: &std::path::Path, forward: bool) -> RuntimeResult<()> {
    // Redirect stdout to /dev/null — kernel console goes to kernel.log
    // via console_output, so nothing useful writes to stdout after the
    // startup JSON. This prevents SIGPIPE when the parent drops the pipe.
    let devnull = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    unsafe {
        libc::dup2(devnull.as_raw_fd(), libc::STDOUT_FILENO);
    }
    drop(devnull);

    // Capture stderr → runtime.log (rotating).
    let (stderr_read, stderr_write) = create_pipe()?;

    let orig_stderr: Option<std::fs::File> = if forward {
        Some(unsafe { std::fs::File::from_raw_fd(libc::dup(libc::STDERR_FILENO)) })
    } else {
        None
    };

    unsafe {
        libc::dup2(stderr_write.as_raw_fd(), libc::STDERR_FILENO);
    }
    drop(stderr_write);

    spawn_log_thread("log-runtime", stderr_read, log_dir, "runtime", orig_stderr)?;

    Ok(())
}

/// Write startup info JSON to stdout.
fn write_startup_info(json: &str) -> RuntimeResult<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{json}")?;
    stdout.flush()?;
    Ok(())
}

/// Connect to the sandbox database.
///
/// Busy timeout uses [`microsandbox_db::pool::DEFAULT_BUSY_TIMEOUT_SECS`]:
/// the in-VM runtime is not user-configurable, so DB tuning policy lives
/// with the host (which honours `~/.microsandbox/config.json`).
async fn connect_db(
    db_path: &std::path::Path,
    connect_timeout_secs: u64,
) -> RuntimeResult<DbWriteConnection> {
    DbWriteConnection::open(
        db_path,
        Duration::from_secs(connect_timeout_secs),
        Duration::from_secs(microsandbox_db::pool::DEFAULT_BUSY_TIMEOUT_SECS),
    )
    .await
    .map_err(|e| RuntimeError::Custom(format!("database connect: {e}")))
}

/// Insert a run record into the database.
async fn insert_run(db: &DbWriteConnection, sandbox_id: i32, pid: u32) -> RuntimeResult<i32> {
    let now = chrono::Utc::now().naive_utc();
    let record = run_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        pid: Set(Some(pid as i32)),
        status: Set(run_entity::RunStatus::Running),
        started_at: Set(Some(now)),
        ..Default::default()
    };
    let result = run_entity::Entity::insert(record)
        .exec(db)
        .await
        .map_err(|e| RuntimeError::Custom(format!("insert run: {e}")))?;
    Ok(result.last_insert_id)
}

/// Mark a run record as failed (Terminated + InternalError) on startup error.
async fn mark_run_failed(db: &DbWriteConnection, run_id: i32) -> RuntimeResult<()> {
    use sea_orm::QueryFilter;
    use sea_orm::sea_query::Expr;

    let now = chrono::Utc::now().naive_utc();
    run_entity::Entity::update_many()
        .col_expr(
            run_entity::Column::Status,
            Expr::value(run_entity::RunStatus::Terminated),
        )
        .col_expr(
            run_entity::Column::TerminationReason,
            Expr::value(run_entity::TerminationReason::InternalError),
        )
        .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
        .filter(run_entity::Column::Id.eq(run_id))
        .exec(db)
        .await
        .map_err(|e| RuntimeError::Custom(format!("mark run failed: {e}")))?;
    Ok(())
}

/// Create a pipe pair, returning `(read_end, write_end)` as `OwnedFd`.
fn create_pipe() -> RuntimeResult<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Spawn a background thread that reads from a pipe and writes to a
/// rotating log file. If `forward` is `Some`, also tees to that file
/// (typically the original stdout/stderr saved before redirect).
fn spawn_log_thread(
    name: &str,
    pipe_read: OwnedFd,
    log_dir: &std::path::Path,
    log_prefix: &str,
    forward: Option<std::fs::File>,
) -> RuntimeResult<()> {
    use crate::logging::RotatingLog;
    use std::io::Read;

    const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

    let log_dir = log_dir.to_path_buf();
    let log_prefix = log_prefix.to_string();

    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let mut log = match RotatingLog::new(&log_dir, &log_prefix, MAX_LOG_BYTES) {
                Ok(log) => log,
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "failed to create {log_prefix} log: {e}");
                    return;
                }
            };
            let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_read.into_raw_fd()) };
            let mut fwd = forward;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = log.write(&buf[..n]);
                        if let Some(ref mut f) = fwd {
                            let _ = std::io::Write::write_all(f, &buf[..n]);
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| RuntimeError::Custom(format!("spawn {name} thread: {e}")))?;

    Ok(())
}

/// Validate a disk image format string.
pub fn validate_disk_format(format: Option<&str>) -> msb_krun::Result<msb_krun::DiskImageFormat> {
    match format.unwrap_or("raw") {
        "qcow2" => Ok(msb_krun::DiskImageFormat::Qcow2),
        "raw" => Ok(msb_krun::DiskImageFormat::Raw),
        "vmdk" => Ok(msb_krun::DiskImageFormat::Vmdk),
        other => Err(msb_krun::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown disk image format: {other}"),
        ))),
    }
}

/// Append the default block root env var if not already set.
pub fn append_block_root_env(env: &mut Vec<String>) {
    let prefix = format!("{}=", microsandbox_protocol::ENV_BLOCK_ROOT);
    if env.iter().any(|entry| entry.starts_with(&prefix)) {
        return;
    }
    env.push(format!("{prefix}/dev/vda"));
}

/// Move the path-bearing `MSB_*` env vars off the kernel command line and
/// into the runtime virtiofs share, so a non-ASCII or whitespace guest path
/// (which libkrun's printable-ASCII-only cmdline validator would reject,
/// `.unwrap()`-panicking the VMM) reaches agentd intact.
///
/// `exec_env` is filtered in place: every `KEY=VALUE` whose `KEY` is in
/// [`microsandbox_protocol::PATH_BEARING_ENV_KEYS`] is removed and appended
/// to `<runtime_dir>/<BOOT_PARAMS_FILE>` as a `KEY\tVALUE\n` line. The TAB
/// framing keeps the value byte-transparent (UTF-8, `':'`, `';'`, spaces all
/// survive). Non-path env stays on the cmdline. The file is written only
/// when at least one such var is present; agentd treats an absent file as
/// "no side-channel mounts" and falls back to the (now-empty) cmdline values.
fn relocate_path_bearing_env(
    runtime_dir: &std::path::Path,
    exec_env: &mut Vec<String>,
) -> RuntimeResult<()> {
    let path = runtime_dir.join(microsandbox_protocol::BOOT_PARAMS_FILE);
    let mut boot_params = String::new();
    let mut kept = Vec::with_capacity(exec_env.len());
    for kv in exec_env.drain(..) {
        match kv.split_once('=') {
            Some((key, value)) if microsandbox_protocol::PATH_BEARING_ENV_KEYS.contains(&key) => {
                // A TAB or newline in the value would break the
                // `KEY\tVALUE\n` framing (TAB mis-splits, newline mis-frames
                // the next line). Callers are expected to screen guest paths
                // — agent-vm rejects control characters before this point —
                // but fail loud here rather than silently corrupt the file.
                if value.contains(['\t', '\n']) {
                    return Err(RuntimeError::Custom(format!(
                        "{key} value contains a tab or newline that the boot-params \
                         channel can't frame: {value:?}"
                    )));
                }
                boot_params.push_str(key);
                boot_params.push('\t');
                boot_params.push_str(value);
                boot_params.push('\n');
            }
            _ => kept.push(kv),
        }
    }
    *exec_env = kept;
    if boot_params.is_empty() {
        // No path-bearing vars this run. Remove any stale file so a reused
        // runtime_dir from an earlier run can't shadow the (now-empty)
        // cmdline values. (agent-vm's per-PID sandbox names make reuse
        // moot, but other SDK callers may reuse a name.)
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(RuntimeError::Custom(format!(
                    "removing stale boot-params {}: {e}",
                    path.display()
                )));
            }
        }
    } else {
        std::fs::write(&path, boot_params).map_err(|e| {
            RuntimeError::Custom(format!("writing boot-params {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

/// Prepend `/.msb/scripts` to PATH for the initial guest command.
pub fn prepend_scripts_path(env: &mut Vec<String>) {
    let scripts = microsandbox_protocol::SCRIPTS_PATH;
    let prefix = "PATH=";

    if let Some(entry) = env.iter_mut().find(|entry| entry.starts_with(prefix)) {
        let existing = &entry[prefix.len()..];
        if !existing.split(':').any(|segment| segment == scripts) {
            *entry = format!("{prefix}{scripts}:{existing}");
        }
    } else {
        env.push(format!(
            "{prefix}{scripts}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ));
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        append_block_root_env, prepend_scripts_path, relocate_path_bearing_env,
        validate_disk_format,
    };

    #[test]
    fn test_validate_disk_format_rejects_unknown_values() {
        let err = validate_disk_format(Some("iso")).unwrap_err();
        assert!(err.to_string().contains("unknown disk image format"));
    }

    #[test]
    fn test_relocate_path_bearing_env_moves_paths_to_file() {
        use microsandbox_protocol::{
            BOOT_PARAMS_FILE, ENV_DIR_MOUNTS, ENV_DISK_MOUNTS, ENV_HOSTNAME,
        };
        let dir = tempfile::tempdir().unwrap();
        // A Cyrillic guest path in MSB_DIR_MOUNTS, a disk mount, and a
        // non-path var that must stay on the cmdline.
        let mut env = vec![
            format!("{ENV_DIR_MOUNTS}=tag_1:/home/boger/проект;st_1:/agent-vm-state"),
            format!("{ENV_DISK_MOUNTS}=data_1:/data:ext4"),
            format!("{ENV_HOSTNAME}=agent-vm-abc"),
            "PATH=/usr/bin".to_string(),
        ];
        relocate_path_bearing_env(dir.path(), &mut env).unwrap();

        // Path-bearing vars are dropped from the cmdline env...
        assert!(!env.iter().any(|e| e.starts_with(&format!("{ENV_DIR_MOUNTS}="))));
        assert!(!env.iter().any(|e| e.starts_with(&format!("{ENV_DISK_MOUNTS}="))));
        // ...non-path vars are kept.
        assert!(env.contains(&format!("{ENV_HOSTNAME}=agent-vm-abc")));
        assert!(env.contains(&"PATH=/usr/bin".to_string()));

        // ...and written verbatim to the boot-params file as KEY\tVALUE\n.
        let body = std::fs::read_to_string(dir.path().join(BOOT_PARAMS_FILE)).unwrap();
        assert!(body.contains(&format!(
            "{ENV_DIR_MOUNTS}\ttag_1:/home/boger/проект;st_1:/agent-vm-state\n"
        )));
        assert!(body.contains(&format!("{ENV_DISK_MOUNTS}\tdata_1:/data:ext4\n")));
        assert!(!body.contains(ENV_HOSTNAME));
    }

    #[test]
    fn test_relocate_path_bearing_env_no_paths_removes_stale_file() {
        use microsandbox_protocol::BOOT_PARAMS_FILE;
        let dir = tempfile::tempdir().unwrap();
        // Pre-seed a stale file from a hypothetical earlier run.
        std::fs::write(dir.path().join(BOOT_PARAMS_FILE), "stale\tdata\n").unwrap();
        let mut env = vec!["PATH=/usr/bin".to_string()];
        relocate_path_bearing_env(dir.path(), &mut env).unwrap();
        assert_eq!(env, vec!["PATH=/usr/bin".to_string()]);
        // With no path-bearing vars, the stale file must be removed so it
        // can't shadow the cmdline.
        assert!(!dir.path().join(BOOT_PARAMS_FILE).exists());
    }

    #[test]
    fn test_relocate_path_bearing_env_rejects_control_char_in_value() {
        use microsandbox_protocol::ENV_DIR_MOUNTS;
        let dir = tempfile::tempdir().unwrap();
        let mut env = vec![format!("{ENV_DIR_MOUNTS}=tag_1:/home/a\nb")];
        let err = relocate_path_bearing_env(dir.path(), &mut env).unwrap_err();
        assert!(
            err.to_string().contains("tab or newline"),
            "expected framing error, got: {err}"
        );
    }

    #[test]
    fn test_append_block_root_env_adds_default_device() {
        let mut env = vec!["FOO=bar".to_string()];
        append_block_root_env(&mut env);
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&format!(
            "{}=/dev/vda",
            microsandbox_protocol::ENV_BLOCK_ROOT
        )));
    }

    #[test]
    fn test_append_block_root_env_preserves_existing_value() {
        let existing = format!(
            "{}=/dev/vdb,fstype=xfs",
            microsandbox_protocol::ENV_BLOCK_ROOT
        );
        let mut env = vec![existing.clone()];
        append_block_root_env(&mut env);
        assert_eq!(env, vec![existing]);
    }

    #[test]
    fn test_prepend_scripts_path_updates_existing_path() {
        let mut env = vec!["PATH=/usr/bin:/bin".to_string()];
        prepend_scripts_path(&mut env);
        assert_eq!(env, vec!["PATH=/.msb/scripts:/usr/bin:/bin".to_string()]);
    }

    #[test]
    fn test_prepend_scripts_path_adds_default_path_when_missing() {
        let mut env = vec!["LANG=C.UTF-8".to_string()];
        prepend_scripts_path(&mut env);
        assert!(
            env.contains(
                &"PATH=/.msb/scripts:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_prepend_scripts_path_avoids_duplicates() {
        let mut env = vec!["PATH=/.msb/scripts:/usr/bin".to_string()];
        prepend_scripts_path(&mut env);
        assert_eq!(env, vec!["PATH=/.msb/scripts:/usr/bin".to_string()]);
    }
}
