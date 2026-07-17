use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::{MaybeUninit, align_of, offset_of, size_of};

use discovery::CancellationToken;
use domain::{AccessLevel, AppError, ErrorCode, FieldValue, ProcessInstanceKey, ProcessStatus};
use windows::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS, SystemProcessInformation,
    SystemProcessorPerformanceInformation,
};
use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation,
    ProcessWow64Information,
};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_ADDRESS,
    ERROR_INVALID_PARAMETER, ERROR_NOACCESS, ERROR_NOT_FOUND, ERROR_PARTIAL_COPY,
    ERROR_PROCESS_ABORTED, FILETIME, HANDLE, NTSTATUS, STATUS_ACCESS_DENIED,
    STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_CID, STATUS_PROCESS_IS_TERMINATING, STILL_ACTIVE, UNICODE_STRING, WIN32_ERROR,
};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::Win32::System::WindowsProgramming::{
    SYSTEM_PROCESS_INFORMATION, SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, SYSTEM_THREAD_INFORMATION,
};
use windows::core::{Error as WindowsError, GUID, PWSTR};

const SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS: SYSTEM_INFORMATION_CLASS =
    SYSTEM_INFORMATION_CLASS(90);
const INITIAL_NATIVE_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_NATIVE_BUFFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_QUERY_ATTEMPTS: usize = 8;
const MAX_PROCESS_IMAGE_UNITS: usize = 32_768;
const MAX_COMMAND_LINE_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_COMMAND_LINE_BUFFER_BYTES: usize =
    MAX_COMMAND_LINE_PAYLOAD_BYTES + size_of::<UNICODE_STRING>();
const MAX_WORKING_DIRECTORY_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
const CANCELLATION_CHECK_INTERVAL: usize = 64;

const PROCESS_CREATE_TIME_RANGE: std::ops::Range<usize> = 24..32;
const PROCESS_USER_TIME_RANGE: std::ops::Range<usize> = 32..40;
const PROCESS_KERNEL_TIME_RANGE: std::ops::Range<usize> = 40..48;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SystemBootEnvironmentInformation {
    boot_identifier: GUID,
    firmware_type: u32,
    reserved: u32,
    boot_flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessBasicInformation64 {
    exit_status: NTSTATUS,
    peb_base_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Peb64Prefix {
    reserved: [u8; 0x20],
    process_parameters: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Peb32Prefix {
    reserved: [u8; 0x10],
    process_parameters: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnicodeString64 {
    length: u16,
    maximum_length: u16,
    padding: u32,
    buffer: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnicodeString32 {
    length: u16,
    maximum_length: u16,
    buffer: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CurrentDirectory64 {
    dos_path: UnicodeString64,
    handle: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CurrentDirectory32 {
    dos_path: UnicodeString32,
    handle: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessParameters64Prefix {
    maximum_length: u32,
    length: u32,
    reserved: [u8; 0x30],
    current_directory: CurrentDirectory64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessParameters32Prefix {
    maximum_length: u32,
    length: u32,
    reserved: [u8; 0x1c],
    current_directory: CurrentDirectory32,
}

const _: () = {
    assert!(size_of::<usize>() == 8);

    assert!(size_of::<SystemBootEnvironmentInformation>() == 32);
    assert!(align_of::<SystemBootEnvironmentInformation>() == 8);
    assert!(offset_of!(SystemBootEnvironmentInformation, boot_identifier) == 0);
    assert!(offset_of!(SystemBootEnvironmentInformation, firmware_type) == 16);
    assert!(offset_of!(SystemBootEnvironmentInformation, boot_flags) == 24);

    assert!(size_of::<ProcessBasicInformation64>() == 48);
    assert!(align_of::<ProcessBasicInformation64>() == 8);
    assert!(offset_of!(ProcessBasicInformation64, exit_status) == 0);
    assert!(offset_of!(ProcessBasicInformation64, peb_base_address) == 8);
    assert!(offset_of!(ProcessBasicInformation64, affinity_mask) == 16);
    assert!(offset_of!(ProcessBasicInformation64, base_priority) == 24);
    assert!(offset_of!(ProcessBasicInformation64, unique_process_id) == 32);
    assert!(offset_of!(ProcessBasicInformation64, inherited_from_unique_process_id) == 40);

    assert!(size_of::<Peb64Prefix>() == 40);
    assert!(align_of::<Peb64Prefix>() == 8);
    assert!(offset_of!(Peb64Prefix, reserved) == 0);
    assert!(offset_of!(Peb64Prefix, process_parameters) == 0x20);

    assert!(size_of::<Peb32Prefix>() == 20);
    assert!(align_of::<Peb32Prefix>() == 4);
    assert!(offset_of!(Peb32Prefix, reserved) == 0);
    assert!(offset_of!(Peb32Prefix, process_parameters) == 0x10);

    assert!(size_of::<UnicodeString64>() == 16);
    assert!(align_of::<UnicodeString64>() == 8);
    assert!(offset_of!(UnicodeString64, length) == 0);
    assert!(offset_of!(UnicodeString64, maximum_length) == 2);
    assert!(offset_of!(UnicodeString64, padding) == 4);
    assert!(offset_of!(UnicodeString64, buffer) == 8);

    assert!(size_of::<UnicodeString32>() == 8);
    assert!(align_of::<UnicodeString32>() == 4);
    assert!(offset_of!(UnicodeString32, length) == 0);
    assert!(offset_of!(UnicodeString32, maximum_length) == 2);
    assert!(offset_of!(UnicodeString32, buffer) == 4);

    assert!(size_of::<CurrentDirectory64>() == 24);
    assert!(align_of::<CurrentDirectory64>() == 8);
    assert!(offset_of!(CurrentDirectory64, dos_path) == 0);
    assert!(offset_of!(CurrentDirectory64, handle) == 16);

    assert!(size_of::<CurrentDirectory32>() == 12);
    assert!(align_of::<CurrentDirectory32>() == 4);
    assert!(offset_of!(CurrentDirectory32, dos_path) == 0);
    assert!(offset_of!(CurrentDirectory32, handle) == 8);

    assert!(size_of::<ProcessParameters64Prefix>() == 80);
    assert!(align_of::<ProcessParameters64Prefix>() == 8);
    assert!(offset_of!(ProcessParameters64Prefix, maximum_length) == 0);
    assert!(offset_of!(ProcessParameters64Prefix, length) == 4);
    assert!(offset_of!(ProcessParameters64Prefix, reserved) == 8);
    assert!(offset_of!(ProcessParameters64Prefix, current_directory) == 0x38);

    assert!(size_of::<ProcessParameters32Prefix>() == 48);
    assert!(align_of::<ProcessParameters32Prefix>() == 4);
    assert!(offset_of!(ProcessParameters32Prefix, maximum_length) == 0);
    assert!(offset_of!(ProcessParameters32Prefix, length) == 4);
    assert!(offset_of!(ProcessParameters32Prefix, reserved) == 8);
    assert!(offset_of!(ProcessParameters32Prefix, current_directory) == 0x24);

    assert!(size_of::<SYSTEM_PROCESS_INFORMATION>() == 256);
    assert!(align_of::<SYSTEM_PROCESS_INFORMATION>() == 8);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, NextEntryOffset) == 0);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, NumberOfThreads) == 4);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, Reserved1) == 8);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, ImageName) == 56);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, UniqueProcessId) == 80);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, Reserved2) == 88);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, WorkingSetSize) == 144);
    assert!(offset_of!(SYSTEM_PROCESS_INFORMATION, Reserved7) == 208);

    assert!(size_of::<SYSTEM_THREAD_INFORMATION>() == 80);
    assert!(align_of::<SYSTEM_THREAD_INFORMATION>() == 8);
    assert!(offset_of!(SYSTEM_THREAD_INFORMATION, StartAddress) == 32);
    assert!(offset_of!(SYSTEM_THREAD_INFORMATION, ClientId) == 40);
    assert!(offset_of!(SYSTEM_THREAD_INFORMATION, ThreadState) == 68);
    assert!(offset_of!(SYSTEM_THREAD_INFORMATION, WaitReason) == 72);

    assert!(size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>() == 48);
    assert!(align_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>() == 8);
    assert!(offset_of!(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, IdleTime) == 0);
    assert!(offset_of!(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, KernelTime) == 8);
    assert!(offset_of!(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, UserTime) == 16);

    assert!(size_of::<UNICODE_STRING>() == 16);
    assert!(align_of::<UNICODE_STRING>() == 8);
    assert!(offset_of!(UNICODE_STRING, Buffer) == 8);
};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NativeSnapshot {
    pub(crate) system_total: Option<u64>,
    pub(crate) processes: Vec<NativeProcessSample>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NativeProcessSample {
    pub(crate) pid: u32,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) create_time: u64,
    pub(crate) user_time: u64,
    pub(crate) kernel_time: u64,
    pub(crate) working_set: u64,
    pub(crate) image_name: FieldValue<String>,
    pub(crate) status: ProcessStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProcessInspection {
    Verified {
        owner_user: FieldValue<String>,
        executable_path: FieldValue<String>,
        access_level: AccessLevel,
    },
    Denied {
        reason: String,
    },
    Gone,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NativeEnrichment {
    pub(crate) executable_path: FieldValue<String>,
    pub(crate) command_line: FieldValue<String>,
    pub(crate) working_directory: FieldValue<String>,
    pub(crate) access_level: AccessLevel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativePathObservation {
    Known(String),
    Unknown,
    AccessLimited(String),
    NotSupported,
}

pub(crate) fn query_boot_identifier() -> Result<String, AppError> {
    let mut information = MaybeUninit::<SystemBootEnvironmentInformation>::zeroed();
    let mut returned = 0_u32;
    // Safety: `information` points to an aligned writable buffer of the exact
    // class-90 structure size and remains live for the duration of the call.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS,
            information.as_mut_ptr().cast(),
            size_of::<SystemBootEnvironmentInformation>() as u32,
            &mut returned,
        )
    };
    if status.is_err() {
        return Err(ntstatus_error("query boot environment", status));
    }
    if returned != size_of::<SystemBootEnvironmentInformation>() as u32 {
        return Err(corrupt_buffer_error(
            "query boot environment",
            "returned structure length does not match the expected ABI",
        ));
    }

    // Safety: a successful native call initialized the complete fixed-size
    // structure; a short successful write was rejected above.
    let information = unsafe { information.assume_init() };
    if information.boot_identifier == GUID::default() {
        return Err(corrupt_buffer_error(
            "query boot environment",
            "boot identifier is zero",
        ));
    }
    Ok(format_guid(information.boot_identifier))
}

fn format_guid(value: GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7],
    )
}

pub(crate) fn query_process_snapshot(
    cancellation: &CancellationToken,
) -> Result<NativeSnapshot, AppError> {
    if cancellation.is_cancelled() {
        return Err(cancelled_error("query process snapshot"));
    }

    let system_total = match query_processor_total(cancellation) {
        Ok(total) => Some(total),
        Err(_) if cancellation.is_cancelled() => {
            return Err(cancelled_error("query processor performance"));
        }
        // Process enumeration remains useful when the optional CPU denominator
        // is unavailable. Callers preserve this distinction as Unknown CPU.
        Err(_) => None,
    };
    let buffer = query_system_buffer(
        SystemProcessInformation,
        "query process information",
        cancellation,
    )?;
    let processes = parse_process_buffer(&buffer, cancellation)?;

    Ok(NativeSnapshot {
        system_total,
        processes,
    })
}

struct AlignedBuffer {
    words: Vec<u64>,
    used_bytes: usize,
}

impl AlignedBuffer {
    fn with_byte_capacity(byte_capacity: usize) -> Result<Self, AppError> {
        let word_count = byte_capacity
            .checked_add(size_of::<u64>() - 1)
            .and_then(|value| value.checked_div(size_of::<u64>()))
            .ok_or_else(|| {
                corrupt_buffer_error("allocate native buffer", "buffer size overflow")
            })?;
        Ok(Self {
            words: vec![0_u64; word_count],
            used_bytes: 0,
        })
    }

    fn byte_capacity(&self) -> usize {
        self.words.len() * size_of::<u64>()
    }

    fn base_address(&self) -> usize {
        self.words.as_ptr() as usize
    }

    fn as_mut_void_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }
}

fn query_system_buffer(
    information_class: SYSTEM_INFORMATION_CLASS,
    operation: &'static str,
    cancellation: &CancellationToken,
) -> Result<AlignedBuffer, AppError> {
    let mut requested_bytes = INITIAL_NATIVE_BUFFER_BYTES;
    for _ in 0..MAX_NATIVE_QUERY_ATTEMPTS {
        if cancellation.is_cancelled() {
            return Err(cancelled_error(operation));
        }

        let mut buffer = AlignedBuffer::with_byte_capacity(requested_bytes)?;
        let capacity = buffer.byte_capacity();
        let capacity_u32 = u32::try_from(capacity).map_err(|_| {
            corrupt_buffer_error(operation, "buffer capacity exceeds native API limit")
        })?;
        let mut returned = 0_u32;
        // Safety: the aligned, initialized allocation is writable for
        // `capacity_u32` bytes and is not moved or reallocated during the call.
        let status = unsafe {
            NtQuerySystemInformation(
                information_class,
                buffer.as_mut_void_ptr(),
                capacity_u32,
                &mut returned,
            )
        };

        if is_resize_status(status) {
            let doubled = capacity.checked_mul(2).unwrap_or(usize::MAX);
            let required = usize::try_from(returned).unwrap_or(usize::MAX);
            let next = doubled.max(required).max(capacity.saturating_add(1));
            if next > MAX_NATIVE_BUFFER_BYTES {
                return Err(native_buffer_limit_error(operation, next));
            }
            requested_bytes = next;
            continue;
        }
        if status.is_err() {
            return Err(ntstatus_error(operation, status));
        }

        let returned = returned as usize;
        if returned > capacity {
            return Err(corrupt_buffer_error(
                operation,
                "native return length exceeds buffer capacity",
            ));
        }
        if returned == 0 {
            return Err(corrupt_buffer_error(
                operation,
                "native query returned a zero effective length",
            ));
        }
        buffer.used_bytes = returned;
        return Ok(buffer);
    }

    Err(native_buffer_limit_error(operation, requested_bytes))
}

fn is_resize_status(status: NTSTATUS) -> bool {
    matches!(
        status,
        STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW
    )
}

fn query_processor_total(cancellation: &CancellationToken) -> Result<u64, AppError> {
    let buffer = query_system_buffer(
        SystemProcessorPerformanceInformation,
        "query processor performance",
        cancellation,
    )?;
    let record_size = size_of::<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION>();
    if buffer.used_bytes == 0 || buffer.used_bytes % record_size != 0 {
        return Err(corrupt_buffer_error(
            "query processor performance",
            "processor buffer has an invalid length",
        ));
    }

    let record_count = buffer.used_bytes / record_size;
    let mut total = 0_u64;
    for index in 0..record_count {
        if index % CANCELLATION_CHECK_INTERVAL == 0 && cancellation.is_cancelled() {
            return Err(cancelled_error("query processor performance"));
        }
        let offset = index.checked_mul(record_size).ok_or_else(|| {
            corrupt_buffer_error("query processor performance", "record offset overflow")
        })?;
        // Safety: record_count was derived from the validated used length and
        // the allocation is aligned for this native structure.
        let record = unsafe {
            std::ptr::read_unaligned(buffer.words.as_ptr().cast::<u8>().add(offset)
                as *const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)
        };
        let kernel = u64::try_from(record.KernelTime).map_err(|_| {
            corrupt_buffer_error("query processor performance", "kernel time is negative")
        })?;
        let user = u64::try_from(record.UserTime).map_err(|_| {
            corrupt_buffer_error("query processor performance", "user time is negative")
        })?;
        total = total
            .checked_add(kernel)
            .and_then(|value| value.checked_add(user))
            .ok_or_else(|| {
                corrupt_buffer_error("query processor performance", "CPU total overflow")
            })?;
    }
    Ok(total)
}

fn parse_process_buffer(
    buffer: &AlignedBuffer,
    cancellation: &CancellationToken,
) -> Result<Vec<NativeProcessSample>, AppError> {
    let header_size = size_of::<SYSTEM_PROCESS_INFORMATION>();
    if buffer.used_bytes < header_size {
        return Err(corrupt_buffer_error(
            "parse process information",
            "buffer is shorter than one process header",
        ));
    }

    let mut offset = 0_usize;
    let mut record_index = 0_usize;
    let mut seen_pids = HashSet::new();
    let mut processes = Vec::new();
    loop {
        if record_index % CANCELLATION_CHECK_INTERVAL == 0 && cancellation.is_cancelled() {
            return Err(cancelled_error("parse process information"));
        }
        if offset % align_of::<SYSTEM_PROCESS_INFORMATION>() != 0 {
            return Err(corrupt_buffer_error(
                "parse process information",
                "process record is misaligned",
            ));
        }
        let header_end = offset.checked_add(header_size).ok_or_else(|| {
            corrupt_buffer_error("parse process information", "header offset overflow")
        })?;
        if header_end > buffer.used_bytes {
            return Err(corrupt_buffer_error(
                "parse process information",
                "process header exceeds buffer",
            ));
        }

        // Safety: the complete fixed header lies in the initialized allocation;
        // read_unaligned avoids creating a reference from native byte storage.
        let record = unsafe {
            std::ptr::read_unaligned(
                buffer.words.as_ptr().cast::<u8>().add(offset) as *const SYSTEM_PROCESS_INFORMATION
            )
        };
        let terminal = record.NextEntryOffset == 0;
        let entry_end = if terminal {
            buffer.used_bytes
        } else {
            let next = record.NextEntryOffset as usize;
            if next < header_size || next % align_of::<SYSTEM_PROCESS_INFORMATION>() != 0 {
                return Err(corrupt_buffer_error(
                    "parse process information",
                    "next process offset is invalid",
                ));
            }
            offset.checked_add(next).ok_or_else(|| {
                corrupt_buffer_error("parse process information", "next offset overflow")
            })?
        };
        if entry_end > buffer.used_bytes || entry_end < header_end {
            return Err(corrupt_buffer_error(
                "parse process information",
                "process record exceeds buffer",
            ));
        }

        let thread_bytes = (record.NumberOfThreads as usize)
            .checked_mul(size_of::<SYSTEM_THREAD_INFORMATION>())
            .ok_or_else(|| {
                corrupt_buffer_error("parse process information", "thread array size overflow")
            })?;
        let thread_end = header_end.checked_add(thread_bytes).ok_or_else(|| {
            corrupt_buffer_error("parse process information", "thread array offset overflow")
        })?;
        if thread_end > entry_end {
            return Err(corrupt_buffer_error(
                "parse process information",
                "thread array exceeds process record",
            ));
        }

        if let Some(sample) = parse_process_record(buffer, offset, &record, cancellation)? {
            if !seen_pids.insert(sample.pid) {
                return Err(corrupt_buffer_error(
                    "parse process information",
                    "process snapshot contains a duplicate PID",
                ));
            }
            processes.push(sample);
        }

        if terminal {
            break;
        }
        offset = entry_end;
        record_index = record_index.checked_add(1).ok_or_else(|| {
            corrupt_buffer_error("parse process information", "record count overflow")
        })?;
    }
    Ok(processes)
}

fn parse_process_record(
    buffer: &AlignedBuffer,
    record_offset: usize,
    record: &SYSTEM_PROCESS_INFORMATION,
    cancellation: &CancellationToken,
) -> Result<Option<NativeProcessSample>, AppError> {
    let pid_value = record.UniqueProcessId.0 as usize;
    let Ok(pid) = u32::try_from(pid_value) else {
        return Err(corrupt_buffer_error(
            "parse process information",
            "process identifier exceeds u32",
        ));
    };
    // The idle process has no actionable creation identity and must not be
    // represented using a fabricated zero start time.
    if pid == 0 {
        return Ok(None);
    }

    let create_time = read_reserved_time(&record.Reserved1, PROCESS_CREATE_TIME_RANGE)?;
    if create_time == 0 {
        return Ok(None);
    }
    let user_time = read_reserved_time(&record.Reserved1, PROCESS_USER_TIME_RANGE)?;
    let kernel_time = read_reserved_time(&record.Reserved1, PROCESS_KERNEL_TIME_RANGE)?;
    let parent_value = record.Reserved2 as usize;
    let parent_pid = if parent_value == 0 {
        None
    } else {
        Some(u32::try_from(parent_value).map_err(|_| {
            corrupt_buffer_error(
                "parse process information",
                "parent process identifier exceeds u32",
            )
        })?)
    };
    let working_set = u64::try_from(record.WorkingSetSize).map_err(|_| {
        corrupt_buffer_error(
            "parse process information",
            "working set exceeds domain range",
        )
    })?;
    let image_name = decode_snapshot_unicode(buffer, record.ImageName)?;
    let status =
        derive_process_status(buffer, record_offset, record.NumberOfThreads, cancellation)?;

    Ok(Some(NativeProcessSample {
        pid,
        parent_pid,
        create_time,
        user_time,
        kernel_time,
        working_set,
        image_name,
        status,
    }))
}

fn read_reserved_time(reserved: &[u8; 48], range: std::ops::Range<usize>) -> Result<u64, AppError> {
    let bytes: [u8; 8] = reserved
        .get(range)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| {
            corrupt_buffer_error("parse process information", "native time offset is invalid")
        })?;
    let value = i64::from_ne_bytes(bytes);
    u64::try_from(value)
        .map_err(|_| corrupt_buffer_error("parse process information", "native time is negative"))
}

fn derive_process_status(
    buffer: &AlignedBuffer,
    record_offset: usize,
    thread_count: u32,
    cancellation: &CancellationToken,
) -> Result<ProcessStatus, AppError> {
    if thread_count == 0 {
        return Ok(ProcessStatus::Unknown);
    }
    let first_thread = record_offset
        .checked_add(size_of::<SYSTEM_PROCESS_INFORMATION>())
        .ok_or_else(|| {
            corrupt_buffer_error("parse process information", "thread offset overflow")
        })?;
    let mut all_waiting = true;
    for index in 0..thread_count as usize {
        if index % CANCELLATION_CHECK_INTERVAL == 0 && cancellation.is_cancelled() {
            return Err(cancelled_error("parse process threads"));
        }
        let offset = index
            .checked_mul(size_of::<SYSTEM_THREAD_INFORMATION>())
            .and_then(|value| first_thread.checked_add(value))
            .ok_or_else(|| {
                corrupt_buffer_error("parse process information", "thread offset overflow")
            })?;
        // Bounds for the complete thread array were checked by the caller.
        let thread = unsafe {
            std::ptr::read_unaligned(
                buffer.words.as_ptr().cast::<u8>().add(offset) as *const SYSTEM_THREAD_INFORMATION
            )
        };
        match thread.ThreadState {
            1 | 2 | 3 | 6 | 7 => return Ok(ProcessStatus::Running),
            5 | 8 | 9 => {}
            _ => all_waiting = false,
        }
    }
    Ok(if all_waiting {
        ProcessStatus::Sleeping
    } else {
        ProcessStatus::Unknown
    })
}

fn decode_snapshot_unicode(
    buffer: &AlignedBuffer,
    value: UNICODE_STRING,
) -> Result<FieldValue<String>, AppError> {
    let length = value.Length as usize;
    if length == 0 {
        return Ok(FieldValue::Unknown);
    }
    if length % size_of::<u16>() != 0 || value.Length > value.MaximumLength {
        return Err(corrupt_buffer_error(
            "parse process information",
            "process image string length is invalid",
        ));
    }
    let address = value.Buffer.0 as usize;
    let base = buffer.base_address();
    let allocation_end = base.checked_add(buffer.used_bytes).ok_or_else(|| {
        corrupt_buffer_error("parse process information", "buffer address overflow")
    })?;
    let string_end = address.checked_add(length).ok_or_else(|| {
        corrupt_buffer_error("parse process information", "string address overflow")
    })?;
    if address < base || address % align_of::<u16>() != 0 || string_end > allocation_end {
        return Err(corrupt_buffer_error(
            "parse process information",
            "process image pointer is outside the snapshot",
        ));
    }

    let unit_count = length / size_of::<u16>();
    // Safety: the integer address range and u16 alignment were validated
    // against the still-live snapshot allocation above.
    let units = unsafe { std::slice::from_raw_parts(address as *const u16, unit_count) };
    let decoded = String::from_utf16_lossy(units);
    Ok(if decoded.is_empty() {
        FieldValue::Unknown
    } else {
        FieldValue::Known(decoded)
    })
}

fn native_buffer_limit_error(operation: &'static str, requested: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows native query exceeded its memory limit",
    );
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error
        .details
        .insert("requestedBytes".into(), requested.to_string());
    error
        .details
        .insert("maximumBytes".into(), MAX_NATIVE_BUFFER_BYTES.to_string());
    error
}

fn ntstatus_error(operation: &'static str, status: NTSTATUS) -> AppError {
    let mut error = AppError::new(ErrorCode::PlatformError, "Windows native query failed");
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error
        .details
        .insert("ntstatus".into(), format!("0x{:08X}", status.0 as u32));
    error
}

fn corrupt_buffer_error(operation: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows native query returned an invalid buffer",
    );
    error.details.insert("operation".into(), operation.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn cancelled_error(operation: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::Timeout, "Windows native operation was cancelled");
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error
}

pub(crate) fn inspect_process(
    sample: &NativeProcessSample,
    cancellation: &CancellationToken,
) -> ProcessInspection {
    if cancellation.is_cancelled() {
        return ProcessInspection::Cancelled;
    }
    let handle = match open_verified_process(sample.pid, sample.create_time) {
        OpenProcessOutcome::Verified(handle) => handle,
        OpenProcessOutcome::Denied(reason) => return ProcessInspection::Denied { reason },
        OpenProcessOutcome::Gone => return ProcessInspection::Gone,
    };
    if cancellation.is_cancelled() {
        return ProcessInspection::Cancelled;
    }

    let executable_path = query_image_path(handle.raw());
    if cancellation.is_cancelled() {
        return ProcessInspection::Cancelled;
    }
    let owner_user = query_owner_sid(handle.raw());
    let access_level = if matches!(owner_user, FieldValue::Known(_))
        && matches!(executable_path, FieldValue::Known(_))
    {
        AccessLevel::Full
    } else {
        AccessLevel::Limited
    };

    ProcessInspection::Verified {
        owner_user,
        executable_path,
        access_level,
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // Safety: this wrapper owns one successful process or token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

enum OpenProcessOutcome {
    Verified(OwnedHandle),
    Denied(String),
    Gone,
}

fn open_verified_process(pid: u32, expected_create_time: u64) -> OpenProcessOutcome {
    // Safety: the PID is only a lookup hint until creation time is verified.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedHandle::new(handle),
        Err(error) => return classify_open_error("openProcess", &error),
    };
    let actual_create_time = match query_handle_times(handle.raw()) {
        Ok((create_time, _, _)) => create_time,
        Err(error) => return classify_open_error("getProcessTimes", &error),
    };
    if actual_create_time != expected_create_time {
        return OpenProcessOutcome::Gone;
    }

    let mut exit_code = 0_u32;
    // Safety: the verified process handle remains owned for this call.
    if unsafe { GetExitCodeProcess(handle.raw(), &mut exit_code) }.is_ok()
        && exit_code != STILL_ACTIVE.0 as u32
    {
        return OpenProcessOutcome::Gone;
    }
    OpenProcessOutcome::Verified(handle)
}

fn classify_open_error(operation: &'static str, error: &WindowsError) -> OpenProcessOutcome {
    match WIN32_ERROR::from_error(error) {
        Some(ERROR_ACCESS_DENIED) => {
            OpenProcessOutcome::Denied(format!("{operation}:accessDenied"))
        }
        Some(ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND) => OpenProcessOutcome::Gone,
        Some(code) => OpenProcessOutcome::Denied(format!("{operation}:win32:{}", code.0)),
        None => OpenProcessOutcome::Denied(format!("{operation}:hresult:{:08X}", error.code().0)),
    }
}

fn query_handle_times(handle: HANDLE) -> Result<(u64, u64, u64), WindowsError> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // Safety: all pointers are writable and the handle remains live.
    unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) }?;
    Ok((
        filetime_value(create),
        filetime_value(user),
        filetime_value(kernel),
    ))
}

fn filetime_value(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn query_image_path(handle: HANDLE) -> FieldValue<String> {
    let mut buffer = vec![0_u16; MAX_PROCESS_IMAGE_UNITS];
    let mut length = buffer.len() as u32;
    // Safety: buffer and length are writable while the handle remains live.
    match unsafe {
        QueryFullProcessImageNameW(
            handle,
            Default::default(),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    } {
        Ok(()) if length > 0 && length as usize <= buffer.len() => {
            let value = String::from_utf16_lossy(&buffer[..length as usize]);
            if value.is_empty() {
                FieldValue::Unknown
            } else {
                FieldValue::Known(value)
            }
        }
        Ok(()) => FieldValue::Unknown,
        Err(error) if WIN32_ERROR::from_error(&error) == Some(ERROR_ACCESS_DENIED) => {
            FieldValue::AccessLimited {
                reason: Some("queryImagePath:accessDenied".into()),
            }
        }
        Err(_) => FieldValue::Unknown,
    }
}

fn query_owner_sid(process: HANDLE) -> FieldValue<String> {
    let mut token = HANDLE::default();
    // Safety: token is writable and TOKEN_QUERY is the only requested right.
    if let Err(error) = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } {
        return if WIN32_ERROR::from_error(&error) == Some(ERROR_ACCESS_DENIED) {
            FieldValue::AccessLimited {
                reason: Some("openProcessToken:accessDenied".into()),
            }
        } else {
            FieldValue::Unknown
        };
    }
    let token = OwnedHandle::new(token);

    let mut required = 0_u32;
    // Safety: the size probe intentionally provides no output buffer.
    let size_result =
        unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut required) };
    match size_result {
        Err(error)
            if WIN32_ERROR::from_error(&error) == Some(ERROR_INSUFFICIENT_BUFFER)
                && required > 0 => {}
        Err(error) if WIN32_ERROR::from_error(&error) == Some(ERROR_ACCESS_DENIED) => {
            return FieldValue::AccessLimited {
                reason: Some("getTokenUser:accessDenied".into()),
            };
        }
        _ => return FieldValue::Unknown,
    }
    let required = required as usize;
    if required > MAX_TOKEN_INFORMATION_BYTES || required < size_of::<TOKEN_USER>() {
        return FieldValue::Unknown;
    }
    let word_count = match required.checked_add(size_of::<u64>() - 1) {
        Some(value) => value / size_of::<u64>(),
        None => return FieldValue::Unknown,
    };
    let mut storage = vec![0_u64; word_count];
    let byte_capacity = storage.len() * size_of::<u64>();
    let mut returned = 0_u32;
    // Safety: storage is aligned and writable; token remains owned.
    let token_result = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            byte_capacity as u32,
            &mut returned,
        )
    };
    if let Err(error) = token_result {
        return if WIN32_ERROR::from_error(&error) == Some(ERROR_ACCESS_DENIED) {
            FieldValue::AccessLimited {
                reason: Some("getTokenUser:accessDenied".into()),
            }
        } else {
            FieldValue::Unknown
        };
    }
    let returned = returned as usize;
    if returned < size_of::<TOKEN_USER>() || returned > byte_capacity {
        return FieldValue::Unknown;
    }

    // Safety: the successful call initialized a complete TOKEN_USER header.
    let token_user = unsafe { std::ptr::read_unaligned(storage.as_ptr().cast::<TOKEN_USER>()) };
    let sid_address = token_user.User.Sid.0 as usize;
    let base = storage.as_ptr() as usize;
    let end = match base.checked_add(returned) {
        Some(end) => end,
        None => return FieldValue::Unknown,
    };
    let sid_header_end = match sid_address.checked_add(8) {
        Some(end) => end,
        None => return FieldValue::Unknown,
    };
    if sid_address < base || sid_header_end > end {
        return FieldValue::Unknown;
    }

    // The SID prefix is in bounds before SubAuthorityCount is inspected.
    let subauthority_count = unsafe { *((sid_address + 1) as *const u8) } as usize;
    let sid_length = match subauthority_count
        .checked_mul(size_of::<u32>())
        .and_then(|value| value.checked_add(8))
    {
        Some(length) => length,
        None => return FieldValue::Unknown,
    };
    if sid_address
        .checked_add(sid_length)
        .is_none_or(|sid_end| sid_end > end)
    {
        return FieldValue::Unknown;
    }
    if unsafe { !IsValidSid(token_user.User.Sid).as_bool() }
        || unsafe { GetLengthSid(token_user.User.Sid) } as usize != sid_length
    {
        return FieldValue::Unknown;
    }

    // Safety: the complete SID range is inside the live token allocation.
    let sid = unsafe { std::slice::from_raw_parts(sid_address as *const u8, sid_length) };
    match format_sid(sid) {
        Some(value) => FieldValue::Known(value),
        None => FieldValue::Unknown,
    }
}

fn format_sid(sid: &[u8]) -> Option<String> {
    let revision = *sid.first()?;
    let count = *sid.get(1)? as usize;
    if revision == 0 || sid.len() != 8_usize.checked_add(count.checked_mul(4)?)? {
        return None;
    }
    let authority = sid
        .get(2..8)?
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | *byte as u64);
    let authority = if authority <= u32::MAX as u64 {
        authority.to_string()
    } else {
        format!("0x{authority:012x}")
    };
    let mut value = format!("S-{revision}-{authority}");
    for index in 0..count {
        let start = 8_usize.checked_add(index.checked_mul(4)?)?;
        let end = start.checked_add(4)?;
        let bytes: [u8; 4] = sid.get(start..end)?.try_into().ok()?;
        value.push('-');
        value.push_str(&u32::from_le_bytes(bytes).to_string());
    }
    Some(value)
}

pub(crate) fn query_enrichment(
    instance_key: &ProcessInstanceKey,
    cancellation: &CancellationToken,
) -> Result<Option<NativeEnrichment>, AppError> {
    if cancellation.is_cancelled() {
        return Err(cancelled_error("enrich process"));
    }
    let current_boot = query_boot_identifier()?;
    if current_boot != instance_key.boot_id {
        return Err(identity_mismatch_error(
            instance_key,
            "boot identifier changed",
        ));
    }
    let expected_create_time = instance_key
        .native_start_time
        .parse::<u64>()
        .map_err(|_| invalid_instance_key_error(instance_key, "native start time is not u64"))?;

    let handle = match open_verified_process(instance_key.pid, expected_create_time) {
        OpenProcessOutcome::Verified(handle) => handle,
        OpenProcessOutcome::Denied(reason) => {
            let limited = FieldValue::AccessLimited {
                reason: Some(reason),
            };
            return Ok(Some(NativeEnrichment {
                executable_path: limited.clone(),
                command_line: limited.clone(),
                working_directory: limited,
                access_level: AccessLevel::Denied,
            }));
        }
        OpenProcessOutcome::Gone => return Ok(None),
    };
    if cancellation.is_cancelled() {
        return Err(cancelled_error("enrich process"));
    }

    let executable_path = query_image_path(handle.raw());
    if cancellation.is_cancelled() {
        return Err(cancelled_error("enrich process"));
    }
    let command_line = query_command_line(handle.raw());
    if cancellation.is_cancelled() {
        return Err(cancelled_error("enrich process"));
    }
    let working_directory =
        match query_working_directory(instance_key.pid, expected_create_time, cancellation)? {
            WorkingDirectoryOutcome::Value(value) => value,
            WorkingDirectoryOutcome::Gone => return Ok(None),
        };
    let access_level = if matches!(executable_path, FieldValue::Known(_))
        && matches!(command_line, FieldValue::Known(_))
        && matches!(working_directory, FieldValue::Known(_))
    {
        AccessLevel::Full
    } else {
        AccessLevel::Limited
    };

    Ok(Some(NativeEnrichment {
        executable_path,
        command_line,
        working_directory,
        access_level,
    }))
}

pub(crate) fn query_verified_working_directory(
    instance_key: &ProcessInstanceKey,
    cancellation: &CancellationToken,
) -> Result<NativePathObservation, AppError> {
    if cancellation.is_cancelled() {
        return Err(cancelled_error("query verified process working directory"));
    }
    if query_boot_identifier()? != instance_key.boot_id {
        return Err(stale_project_observation_error(
            instance_key,
            "boot identifier changed before the working-directory query",
        ));
    }
    if cancellation.is_cancelled() {
        return Err(cancelled_error("query verified process working directory"));
    }
    let expected_create_time = instance_key
        .native_start_time
        .parse::<u64>()
        .map_err(|_| invalid_instance_key_error(instance_key, "native start time is not u64"))?;
    let observation =
        match query_working_directory(instance_key.pid, expected_create_time, cancellation)? {
            WorkingDirectoryOutcome::Value(FieldValue::Known(path)) => {
                NativePathObservation::Known(path)
            }
            WorkingDirectoryOutcome::Value(FieldValue::Unknown) => NativePathObservation::Unknown,
            WorkingDirectoryOutcome::Value(FieldValue::AccessLimited { reason }) => {
                NativePathObservation::AccessLimited(
                    reason.unwrap_or_else(|| "queryWorkingDirectory:accessLimited".into()),
                )
            }
            WorkingDirectoryOutcome::Value(FieldValue::NotSupported) => {
                NativePathObservation::NotSupported
            }
            WorkingDirectoryOutcome::Gone => {
                return Err(stale_project_observation_error(
                    instance_key,
                    "process disappeared during the working-directory query",
                ));
            }
        };

    if cancellation.is_cancelled() {
        return Err(cancelled_error("revalidate process working directory"));
    }
    if query_boot_identifier()? != instance_key.boot_id {
        return Err(stale_project_observation_error(
            instance_key,
            "boot identifier changed after the working-directory query",
        ));
    }
    Ok(observation)
}

enum WorkingDirectoryOutcome {
    Value(FieldValue<String>),
    Gone,
}

enum WorkingDirectoryFailure {
    AccessLimited(String),
    Gone,
    Unknown,
    Platform(AppError),
}

type WorkingDirectoryResult<T> = Result<T, WorkingDirectoryFailure>;

#[derive(Clone, Copy)]
enum ProcessPebLocation {
    Native64(usize),
    Wow64(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkingDirectoryLayout {
    Native64,
    Wow64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemoteWorkingDirectory {
    layout: WorkingDirectoryLayout,
    header_address: usize,
    length: u16,
    maximum_length: u16,
    buffer_address: usize,
}

fn query_working_directory(
    pid: u32,
    expected_create_time: u64,
    cancellation: &CancellationToken,
) -> Result<WorkingDirectoryOutcome, AppError> {
    match query_working_directory_inner(pid, expected_create_time, cancellation) {
        Ok(units) => match String::from_utf16(&units) {
            Ok(value) if !value.is_empty() && !value.contains('\0') => {
                Ok(WorkingDirectoryOutcome::Value(FieldValue::Known(value)))
            }
            Ok(_) => Ok(WorkingDirectoryOutcome::Value(FieldValue::Unknown)),
            Err(_) => Ok(WorkingDirectoryOutcome::Value(FieldValue::NotSupported)),
        },
        Err(WorkingDirectoryFailure::AccessLimited(reason)) => {
            Ok(WorkingDirectoryOutcome::Value(FieldValue::AccessLimited {
                reason: Some(reason),
            }))
        }
        Err(WorkingDirectoryFailure::Gone) => Ok(WorkingDirectoryOutcome::Gone),
        Err(WorkingDirectoryFailure::Unknown) => {
            Ok(WorkingDirectoryOutcome::Value(FieldValue::Unknown))
        }
        Err(WorkingDirectoryFailure::Platform(error)) => Err(error),
    }
}

fn query_working_directory_inner(
    pid: u32,
    expected_create_time: u64,
    cancellation: &CancellationToken,
) -> WorkingDirectoryResult<Vec<u16>> {
    check_working_directory_cancelled(cancellation)?;
    let handle = open_working_directory_process(pid)?;
    check_working_directory_cancelled(cancellation)?;
    verify_working_directory_process(&handle, expected_create_time, cancellation)?;
    check_working_directory_cancelled(cancellation)?;

    let read_result = query_working_directory_from_handle(handle.raw(), cancellation);

    // Revalidate even when a PEB read was malformed so process exit or PID
    // reuse cannot be reported as a stable field-level unknown.
    check_working_directory_cancelled(cancellation)?;
    verify_working_directory_process(&handle, expected_create_time, cancellation)?;
    check_working_directory_cancelled(cancellation)?;
    read_result
}

fn open_working_directory_process(pid: u32) -> WorkingDirectoryResult<OwnedHandle> {
    let rights = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
    // Safety: the PID remains only a lookup hint until the returned handle is
    // checked against the expected process creation time.
    match unsafe { OpenProcess(rights, false, pid) } {
        Ok(handle) => Ok(OwnedHandle::new(handle)),
        Err(error) => Err(classify_working_directory_win32_error(
            "openWorkingDirectoryProcess",
            &error,
            WorkingDirectoryWin32Context::Process,
        )),
    }
}

fn verify_working_directory_process(
    handle: &OwnedHandle,
    expected_create_time: u64,
    cancellation: &CancellationToken,
) -> WorkingDirectoryResult<()> {
    let (actual_create_time, _, _) = query_handle_times(handle.raw()).map_err(|error| {
        classify_working_directory_win32_error(
            "getWorkingDirectoryProcessTimes",
            &error,
            WorkingDirectoryWin32Context::Process,
        )
    })?;
    if actual_create_time != expected_create_time {
        return Err(WorkingDirectoryFailure::Gone);
    }

    check_working_directory_cancelled(cancellation)?;
    let mut exit_code = 0_u32;
    // Safety: the VM-read handle is still owned and includes query rights.
    unsafe { GetExitCodeProcess(handle.raw(), &mut exit_code) }.map_err(|error| {
        classify_working_directory_win32_error(
            "getWorkingDirectoryExitCode",
            &error,
            WorkingDirectoryWin32Context::Process,
        )
    })?;
    if exit_code != STILL_ACTIVE.0 as u32 {
        return Err(WorkingDirectoryFailure::Gone);
    }
    Ok(())
}

fn query_working_directory_from_handle(
    handle: HANDLE,
    cancellation: &CancellationToken,
) -> WorkingDirectoryResult<Vec<u16>> {
    let peb = query_process_peb_location(handle, cancellation)?;
    check_working_directory_cancelled(cancellation)?;
    let descriptor = query_working_directory_descriptor(handle, peb, cancellation)?;
    check_working_directory_cancelled(cancellation)?;
    let unit_count = validate_working_directory_descriptor(descriptor)?;
    let units = read_remote_utf16(
        handle,
        descriptor.buffer_address,
        unit_count,
        "readWorkingDirectory",
    )?;
    check_working_directory_cancelled(cancellation)?;
    let descriptor_after = reread_working_directory_descriptor(handle, descriptor)?;
    if descriptor_after != descriptor {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    Ok(units)
}

fn query_process_peb_location(
    handle: HANDLE,
    cancellation: &CancellationToken,
) -> WorkingDirectoryResult<ProcessPebLocation> {
    let wow64_peb =
        query_fixed_process_information::<usize>(handle, ProcessWow64Information, "queryWow64Peb")?;
    if wow64_peb != 0 {
        if wow64_peb > u32::MAX as usize || wow64_peb % align_of::<Peb32Prefix>() != 0 {
            return Err(WorkingDirectoryFailure::Unknown);
        }
        return Ok(ProcessPebLocation::Wow64(wow64_peb));
    }

    check_working_directory_cancelled(cancellation)?;
    let basic = query_fixed_process_information::<ProcessBasicInformation64>(
        handle,
        ProcessBasicInformation,
        "queryBasicProcessInformation",
    )?;
    if basic.peb_base_address == 0 || basic.peb_base_address % align_of::<Peb64Prefix>() != 0 {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    Ok(ProcessPebLocation::Native64(basic.peb_base_address))
}

fn query_fixed_process_information<T: Copy>(
    handle: HANDLE,
    information_class: windows::Wdk::System::Threading::PROCESSINFOCLASS,
    operation: &'static str,
) -> WorkingDirectoryResult<T> {
    let mut value = MaybeUninit::<T>::zeroed();
    let mut returned = 0_u32;
    // Safety: the output is aligned, writable, and exactly the asserted ABI
    // size for the requested fixed-size information class.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            information_class,
            value.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            &mut returned,
        )
    };
    if status == STATUS_ACCESS_DENIED {
        return Err(WorkingDirectoryFailure::AccessLimited(format!(
            "{operation}:accessDenied"
        )));
    }
    if matches!(status, STATUS_INVALID_CID | STATUS_PROCESS_IS_TERMINATING) {
        return Err(WorkingDirectoryFailure::Gone);
    }
    if status.is_err() {
        return Err(WorkingDirectoryFailure::Platform(ntstatus_error(
            operation, status,
        )));
    }
    if returned as usize != size_of::<T>() {
        return Err(WorkingDirectoryFailure::Platform(corrupt_buffer_error(
            operation,
            "returned structure length does not match the expected ABI",
        )));
    }
    // Safety: the successful query reported a complete fixed-size value.
    Ok(unsafe { value.assume_init() })
}

fn query_working_directory_descriptor(
    handle: HANDLE,
    peb: ProcessPebLocation,
    cancellation: &CancellationToken,
) -> WorkingDirectoryResult<RemoteWorkingDirectory> {
    match peb {
        ProcessPebLocation::Native64(peb_address) => {
            let peb = read_remote_exact::<Peb64Prefix>(handle, peb_address, "readPeb64")?;
            check_working_directory_cancelled(cancellation)?;
            let parameters_address = peb.process_parameters;
            let parameters = read_remote_exact::<ProcessParameters64Prefix>(
                handle,
                parameters_address,
                "readProcessParameters64",
            )?;
            validate_process_parameters(
                parameters.length,
                parameters.maximum_length,
                size_of::<ProcessParameters64Prefix>(),
            )?;
            let header_address = parameters_address
                .checked_add(offset_of!(ProcessParameters64Prefix, current_directory))
                .ok_or(WorkingDirectoryFailure::Unknown)?;
            Ok(RemoteWorkingDirectory {
                layout: WorkingDirectoryLayout::Native64,
                header_address,
                length: parameters.current_directory.dos_path.length,
                maximum_length: parameters.current_directory.dos_path.maximum_length,
                buffer_address: parameters.current_directory.dos_path.buffer,
            })
        }
        ProcessPebLocation::Wow64(peb_address) => {
            let peb = read_remote_exact::<Peb32Prefix>(handle, peb_address, "readPeb32")?;
            check_working_directory_cancelled(cancellation)?;
            let parameters_address = peb.process_parameters as usize;
            let parameters = read_remote_exact::<ProcessParameters32Prefix>(
                handle,
                parameters_address,
                "readProcessParameters32",
            )?;
            validate_process_parameters(
                parameters.length,
                parameters.maximum_length,
                size_of::<ProcessParameters32Prefix>(),
            )?;
            let header_address = parameters_address
                .checked_add(offset_of!(ProcessParameters32Prefix, current_directory))
                .ok_or(WorkingDirectoryFailure::Unknown)?;
            Ok(RemoteWorkingDirectory {
                layout: WorkingDirectoryLayout::Wow64,
                header_address,
                length: parameters.current_directory.dos_path.length,
                maximum_length: parameters.current_directory.dos_path.maximum_length,
                buffer_address: parameters.current_directory.dos_path.buffer as usize,
            })
        }
    }
}

fn validate_process_parameters(
    length: u32,
    maximum_length: u32,
    required_prefix_bytes: usize,
) -> WorkingDirectoryResult<()> {
    if length > maximum_length || (length as usize) < required_prefix_bytes {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    Ok(())
}

fn validate_working_directory_descriptor(
    descriptor: RemoteWorkingDirectory,
) -> WorkingDirectoryResult<usize> {
    let length = descriptor.length as usize;
    let maximum_length = descriptor.maximum_length as usize;
    if length == 0
        || length > MAX_WORKING_DIRECTORY_PAYLOAD_BYTES
        || length % size_of::<u16>() != 0
        || maximum_length % size_of::<u16>() != 0
        || length > maximum_length
        || descriptor.buffer_address == 0
        || descriptor.buffer_address % align_of::<u16>() != 0
        || descriptor.buffer_address.checked_add(length).is_none()
    {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    Ok(length / size_of::<u16>())
}

fn reread_working_directory_descriptor(
    handle: HANDLE,
    descriptor: RemoteWorkingDirectory,
) -> WorkingDirectoryResult<RemoteWorkingDirectory> {
    match descriptor.layout {
        WorkingDirectoryLayout::Native64 => {
            let value = read_remote_exact::<UnicodeString64>(
                handle,
                descriptor.header_address,
                "rereadWorkingDirectory64",
            )?;
            Ok(RemoteWorkingDirectory {
                layout: descriptor.layout,
                header_address: descriptor.header_address,
                length: value.length,
                maximum_length: value.maximum_length,
                buffer_address: value.buffer,
            })
        }
        WorkingDirectoryLayout::Wow64 => {
            let value = read_remote_exact::<UnicodeString32>(
                handle,
                descriptor.header_address,
                "rereadWorkingDirectory32",
            )?;
            Ok(RemoteWorkingDirectory {
                layout: descriptor.layout,
                header_address: descriptor.header_address,
                length: value.length,
                maximum_length: value.maximum_length,
                buffer_address: value.buffer as usize,
            })
        }
    }
}

fn read_remote_exact<T: Copy>(
    handle: HANDLE,
    address: usize,
    operation: &'static str,
) -> WorkingDirectoryResult<T> {
    let byte_count = size_of::<T>();
    if address == 0 || address % align_of::<T>() != 0 || address.checked_add(byte_count).is_none() {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    let mut value = MaybeUninit::<T>::uninit();
    let mut bytes_read = 0_usize;
    // Safety: the local output is aligned and writable for exactly byte_count
    // bytes; the remote range was checked for null and address overflow.
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            value.as_mut_ptr().cast(),
            byte_count,
            Some(&mut bytes_read),
        )
    }
    .map_err(|error| {
        classify_working_directory_win32_error(
            operation,
            &error,
            WorkingDirectoryWin32Context::RemoteMemory,
        )
    })?;
    if bytes_read != byte_count {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    // Safety: an exact successful read initialized the complete value.
    Ok(unsafe { value.assume_init() })
}

fn read_remote_utf16(
    handle: HANDLE,
    address: usize,
    unit_count: usize,
    operation: &'static str,
) -> WorkingDirectoryResult<Vec<u16>> {
    let byte_count = unit_count
        .checked_mul(size_of::<u16>())
        .ok_or(WorkingDirectoryFailure::Unknown)?;
    if byte_count == 0
        || byte_count > MAX_WORKING_DIRECTORY_PAYLOAD_BYTES
        || address == 0
        || address % align_of::<u16>() != 0
        || address.checked_add(byte_count).is_none()
    {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    let mut units = vec![0_u16; unit_count];
    let mut bytes_read = 0_usize;
    // Safety: the initialized local vector has byte_count writable bytes and
    // the complete remote range was checked before calling the native API.
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            units.as_mut_ptr().cast(),
            byte_count,
            Some(&mut bytes_read),
        )
    }
    .map_err(|error| {
        classify_working_directory_win32_error(
            operation,
            &error,
            WorkingDirectoryWin32Context::RemoteMemory,
        )
    })?;
    if bytes_read != byte_count {
        return Err(WorkingDirectoryFailure::Unknown);
    }
    Ok(units)
}

#[derive(Clone, Copy)]
enum WorkingDirectoryWin32Context {
    Process,
    RemoteMemory,
}

fn classify_working_directory_win32_error(
    operation: &'static str,
    error: &WindowsError,
    context: WorkingDirectoryWin32Context,
) -> WorkingDirectoryFailure {
    match WIN32_ERROR::from_error(error) {
        Some(ERROR_ACCESS_DENIED) => {
            WorkingDirectoryFailure::AccessLimited(format!("{operation}:accessDenied"))
        }
        Some(ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND | ERROR_PROCESS_ABORTED) => {
            WorkingDirectoryFailure::Gone
        }
        Some(ERROR_INVALID_ADDRESS | ERROR_NOACCESS | ERROR_PARTIAL_COPY)
            if matches!(context, WorkingDirectoryWin32Context::RemoteMemory) =>
        {
            WorkingDirectoryFailure::Unknown
        }
        _ => WorkingDirectoryFailure::Platform(working_directory_win32_error(operation, error)),
    }
}

fn working_directory_win32_error(operation: &'static str, error: &WindowsError) -> AppError {
    let mut app_error = AppError::new(
        ErrorCode::PlatformError,
        "Windows working-directory query failed",
    );
    app_error.retryable = true;
    app_error
        .details
        .insert("operation".into(), operation.into());
    if let Some(code) = WIN32_ERROR::from_error(error) {
        app_error
            .details
            .insert("win32Code".into(), code.0.to_string());
    } else {
        app_error
            .details
            .insert("hresult".into(), format!("0x{:08X}", error.code().0 as u32));
    }
    app_error
}

fn check_working_directory_cancelled(
    cancellation: &CancellationToken,
) -> WorkingDirectoryResult<()> {
    if cancellation.is_cancelled() {
        Err(WorkingDirectoryFailure::Platform(cancelled_error(
            "query working directory",
        )))
    } else {
        Ok(())
    }
}

fn query_command_line(handle: HANDLE) -> FieldValue<String> {
    let mut buffer = match AlignedBuffer::with_byte_capacity(MAX_COMMAND_LINE_BUFFER_BYTES) {
        Ok(buffer) => buffer,
        Err(_) => return FieldValue::Unknown,
    };
    let capacity = buffer.byte_capacity();
    let mut returned = 0_u32;
    // Safety: the verified handle remains live and the output is aligned,
    // writable, and bounded to the maximum payload plus its header.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessCommandLineInformation,
            buffer.as_mut_void_ptr(),
            capacity as u32,
            &mut returned,
        )
    };
    if status == STATUS_ACCESS_DENIED {
        return FieldValue::AccessLimited {
            reason: Some("queryCommandLine:accessDenied".into()),
        };
    }
    if matches!(status, STATUS_INVALID_CID | STATUS_PROCESS_IS_TERMINATING) || status.is_err() {
        return FieldValue::Unknown;
    }
    let used = returned as usize;
    if used < size_of::<UNICODE_STRING>() || used > capacity {
        return FieldValue::Unknown;
    }
    buffer.used_bytes = used;

    // Safety: the validated returned length includes the fixed header.
    let value = unsafe { std::ptr::read_unaligned(buffer.words.as_ptr().cast::<UNICODE_STRING>()) };
    decode_owned_unicode(&buffer, value)
        .map(FieldValue::Known)
        .unwrap_or(FieldValue::Unknown)
}

fn decode_owned_unicode(buffer: &AlignedBuffer, value: UNICODE_STRING) -> Option<String> {
    let length = value.Length as usize;
    if length == 0
        || length > MAX_COMMAND_LINE_PAYLOAD_BYTES
        || length % size_of::<u16>() != 0
        || value.Length > value.MaximumLength
    {
        return None;
    }
    let address = value.Buffer.0 as usize;
    let base = buffer.base_address();
    let end = base.checked_add(buffer.used_bytes)?;
    let string_end = address.checked_add(length)?;
    if address < base || address % align_of::<u16>() != 0 || string_end > end {
        return None;
    }
    // Safety: the complete aligned UTF-16 range is inside the live allocation.
    let units =
        unsafe { std::slice::from_raw_parts(address as *const u16, length / size_of::<u16>()) };
    let value = String::from_utf16_lossy(units);
    (!value.is_empty()).then_some(value)
}

fn identity_mismatch_error(instance_key: &ProcessInstanceKey, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "process instance identity no longer matches",
    );
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_instance_key_error(instance_key: &ProcessInstanceKey, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "process instance key is invalid",
    );
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn stale_project_observation_error(
    instance_key: &ProcessInstanceKey,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "Windows project scan no longer matches the process instance",
    );
    error.retryable = true;
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}
