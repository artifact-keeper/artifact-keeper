use std::ffi::OsString;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "ArtifactKeeper";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

windows_service::define_windows_service!(ffi_service_main, service_main);

pub fn run_as_service() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("Service failed: {e}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let shutdown_token = CancellationToken::new();
    let token_clone = shutdown_token.clone();

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                token_clone.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

    // Report that the service is starting
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    })?;

    // Build the tokio runtime on this thread (can't use #[tokio::main] in service mode)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Report running
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Run the server with our shutdown token
    let result = runtime.block_on(crate::run_server(Some(shutdown_token)));

    // Report stopped
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    result.map_err(|e| e.to_string())?;
    Ok(())
}

pub fn install_service(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let binary_path = std::env::current_exe()?;

    // Check for --config-dir argument
    let config_dir = args
        .windows(2)
        .find(|w| w[0] == "--config-dir")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| r"C:\ProgramData\ArtifactKeeper".to_string());

    let launch_args = vec![
        OsString::from("--service"),
        OsString::from("--config-dir"),
        OsString::from(&config_dir),
    ];

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Artifact Keeper"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path,
        launch_arguments: launch_args,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description("Artifact Keeper - Enterprise artifact registry")?;

    // Create data directory
    let data_dir = PathBuf::from(&config_dir);
    std::fs::create_dir_all(data_dir.join("artifacts"))?;
    std::fs::create_dir_all(data_dir.join("plugins"))?;
    std::fs::create_dir_all(data_dir.join("logs"))?;
    std::fs::create_dir_all(data_dir.join("config"))?;

    info!("Service '{}' installed successfully", SERVICE_NAME);
    info!("Data directory: {}", config_dir);
    info!("Edit the configuration at: {}\\config\\.env", config_dir);
    info!("Start the service with: sc.exe start {}", SERVICE_NAME);

    Ok(())
}

pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;

    // Stop the service if it's running
    let status = service.query_status()?;
    if status.current_state != ServiceState::Stopped {
        info!("Stopping service...");
        service.stop()?;
        // Wait briefly for stop
        std::thread::sleep(Duration::from_secs(3));
    }

    service.delete()?;
    info!("Service '{}' uninstalled successfully", SERVICE_NAME);

    Ok(())
}
