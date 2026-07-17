use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};

use discovery::CancellationToken;
use domain::{AddressFamily, AppError, ErrorCode, FieldValue, PortProtocol, PortState};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_NOT_SUPPORTED,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

const MAX_TABLE_BUFFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_TABLE_QUERY_ATTEMPTS: usize = 8;
const MAX_NATIVE_PORT_ROWS: usize = 1_000_000;
const CANCELLATION_CHECK_INTERVAL: usize = 64;

const _: () = {
    assert!(size_of::<MIB_TCPROW_OWNER_PID>() == 24);
    assert!(align_of::<MIB_TCPROW_OWNER_PID>() == 4);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwState) == 0);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwLocalAddr) == 4);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwLocalPort) == 8);
    assert!(offset_of!(MIB_TCPROW_OWNER_PID, dwOwningPid) == 20);

    assert!(size_of::<MIB_TCP6ROW_OWNER_PID>() == 56);
    assert!(align_of::<MIB_TCP6ROW_OWNER_PID>() == 4);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, ucLocalAddr) == 0);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwLocalScopeId) == 16);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwLocalPort) == 20);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwState) == 48);
    assert!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwOwningPid) == 52);

    assert!(size_of::<MIB_UDPROW_OWNER_PID>() == 12);
    assert!(align_of::<MIB_UDPROW_OWNER_PID>() == 4);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwLocalAddr) == 0);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwLocalPort) == 4);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwOwningPid) == 8);

    assert!(size_of::<MIB_UDP6ROW_OWNER_PID>() == 28);
    assert!(align_of::<MIB_UDP6ROW_OWNER_PID>() == 4);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, ucLocalAddr) == 0);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwLocalScopeId) == 16);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwLocalPort) == 20);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwOwningPid) == 24);
};

#[derive(Clone, Debug)]
pub(crate) struct NativePortRow {
    pub(crate) pid: u32,
    pub(crate) protocol: PortProtocol,
    pub(crate) address_family: AddressFamily,
    pub(crate) local_address: String,
    pub(crate) local_port: u16,
    pub(crate) state: FieldValue<PortState>,
}

pub(crate) fn query_port_rows(
    cancellation: &CancellationToken,
) -> Result<FieldValue<Vec<NativePortRow>>, AppError> {
    let mut rows = Vec::new();
    for specification in [
        TableSpecification::TcpIpv4,
        TableSpecification::TcpIpv6,
        TableSpecification::UdpIpv4,
        TableSpecification::UdpIpv6,
    ] {
        check_cancelled(cancellation, specification)?;
        let remaining_rows = MAX_NATIVE_PORT_ROWS
            .checked_sub(rows.len())
            .ok_or_else(|| row_limit_error(specification, 0, 0))?;
        match query_table(specification, cancellation, remaining_rows)? {
            FieldValue::Known(mut table_rows) => rows.append(&mut table_rows),
            FieldValue::AccessLimited { reason } => {
                return Ok(FieldValue::AccessLimited { reason });
            }
            FieldValue::NotSupported => return Ok(FieldValue::NotSupported),
            FieldValue::Unknown => return Ok(FieldValue::Unknown),
        }
    }
    Ok(FieldValue::Known(rows))
}

#[derive(Clone, Copy)]
enum TableSpecification {
    TcpIpv4,
    TcpIpv6,
    UdpIpv4,
    UdpIpv6,
}

impl TableSpecification {
    fn operation(self) -> &'static str {
        match self {
            Self::TcpIpv4 | Self::TcpIpv6 => "GetExtendedTcpTable",
            Self::UdpIpv4 | Self::UdpIpv6 => "GetExtendedUdpTable",
        }
    }

    fn family(self) -> &'static str {
        match self {
            Self::TcpIpv4 | Self::UdpIpv4 => "IPv4",
            Self::TcpIpv6 | Self::UdpIpv6 => "IPv6",
        }
    }

    fn call(self, buffer: Option<*mut c_void>, size: &mut u32) -> u32 {
        match self {
            Self::TcpIpv4 => {
                // Safety: the caller provides either no buffer for the sizing
                // probe or a writable allocation whose byte length is `size`.
                unsafe {
                    GetExtendedTcpTable(
                        buffer,
                        size,
                        false,
                        u32::from(AF_INET.0),
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    )
                }
            }
            Self::TcpIpv6 => {
                // Safety: see the TcpIpv4 branch above.
                unsafe {
                    GetExtendedTcpTable(
                        buffer,
                        size,
                        false,
                        u32::from(AF_INET6.0),
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    )
                }
            }
            Self::UdpIpv4 => {
                // Safety: see the TcpIpv4 branch above.
                unsafe {
                    GetExtendedUdpTable(
                        buffer,
                        size,
                        false,
                        u32::from(AF_INET.0),
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                }
            }
            Self::UdpIpv6 => {
                // Safety: see the TcpIpv4 branch above.
                unsafe {
                    GetExtendedUdpTable(
                        buffer,
                        size,
                        false,
                        u32::from(AF_INET6.0),
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                }
            }
        }
    }
}

struct AlignedBuffer {
    words: Vec<u64>,
    used_bytes: usize,
}

impl AlignedBuffer {
    fn with_byte_capacity(
        byte_capacity: usize,
        specification: TableSpecification,
    ) -> Result<Self, AppError> {
        let word_count = byte_capacity
            .checked_add(size_of::<u64>() - 1)
            .and_then(|value| value.checked_div(size_of::<u64>()))
            .ok_or_else(|| buffer_limit_error(specification, byte_capacity))?;
        Ok(Self {
            words: vec![0; word_count],
            used_bytes: 0,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    fn bytes(&self) -> &[u8] {
        // Safety: `used_bytes` is accepted only after checking it against the
        // requested allocation size. The word allocation remains live here.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.used_bytes) }
    }
}

fn query_table(
    specification: TableSpecification,
    cancellation: &CancellationToken,
    maximum_rows: usize,
) -> Result<FieldValue<Vec<NativePortRow>>, AppError> {
    let mut required = 0_u32;
    let probe_code = specification.call(None, &mut required);
    match probe_code {
        0 if required == 0 => return Ok(FieldValue::Known(Vec::new())),
        code if code == 0 || code == ERROR_INSUFFICIENT_BUFFER.0 => {}
        code if code == ERROR_NO_DATA.0 => return Ok(FieldValue::Known(Vec::new())),
        code if code == ERROR_ACCESS_DENIED.0 => {
            return Ok(access_limited(specification, code));
        }
        code if code == ERROR_NOT_SUPPORTED.0 => return Ok(FieldValue::NotSupported),
        code => return Err(win32_error(specification, code)),
    }

    let mut requested = required as usize;
    if requested == 0 {
        return Err(invalid_buffer_error(
            specification,
            "sizing probe returned no required length",
        ));
    }
    ensure_within_limit(specification, requested)?;

    for _ in 0..MAX_TABLE_QUERY_ATTEMPTS {
        check_cancelled(cancellation, specification)?;
        let mut buffer = AlignedBuffer::with_byte_capacity(requested, specification)?;
        let mut returned =
            u32::try_from(requested).map_err(|_| buffer_limit_error(specification, requested))?;
        let code = specification.call(Some(buffer.as_mut_ptr()), &mut returned);
        match code {
            0 => {
                let used_bytes = returned as usize;
                if used_bytes > requested {
                    return Err(invalid_buffer_error(
                        specification,
                        "returned length exceeds the supplied buffer",
                    ));
                }
                if used_bytes < size_of::<u32>() {
                    return Err(invalid_buffer_error(
                        specification,
                        "successful table is shorter than its entry count",
                    ));
                }
                buffer.used_bytes = used_bytes;
                return parse_table(&buffer, specification, maximum_rows, cancellation)
                    .map(FieldValue::Known);
            }
            code if code == ERROR_INSUFFICIENT_BUFFER.0 => {
                let reported = returned as usize;
                let doubled = requested
                    .checked_mul(2)
                    .ok_or_else(|| buffer_limit_error(specification, requested))?;
                requested = if reported > requested {
                    reported
                } else {
                    doubled
                };
                ensure_within_limit(specification, requested)?;
            }
            code if code == ERROR_NO_DATA.0 => return Ok(FieldValue::Known(Vec::new())),
            code if code == ERROR_ACCESS_DENIED.0 => {
                return Ok(access_limited(specification, code));
            }
            code if code == ERROR_NOT_SUPPORTED.0 => return Ok(FieldValue::NotSupported),
            code => return Err(win32_error(specification, code)),
        }
    }

    Err(buffer_limit_error(specification, requested))
}

fn parse_table(
    buffer: &AlignedBuffer,
    specification: TableSpecification,
    maximum_rows: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<NativePortRow>, AppError> {
    match specification {
        TableSpecification::TcpIpv4 => parse_rows::<MIB_TCPROW_OWNER_PID>(
            buffer,
            specification,
            maximum_rows,
            cancellation,
            convert_tcp_ipv4,
        ),
        TableSpecification::TcpIpv6 => parse_rows::<MIB_TCP6ROW_OWNER_PID>(
            buffer,
            specification,
            maximum_rows,
            cancellation,
            convert_tcp_ipv6,
        ),
        TableSpecification::UdpIpv4 => parse_rows::<MIB_UDPROW_OWNER_PID>(
            buffer,
            specification,
            maximum_rows,
            cancellation,
            convert_udp_ipv4,
        ),
        TableSpecification::UdpIpv6 => parse_rows::<MIB_UDP6ROW_OWNER_PID>(
            buffer,
            specification,
            maximum_rows,
            cancellation,
            convert_udp_ipv6,
        ),
    }
}

fn parse_rows<T: Copy>(
    buffer: &AlignedBuffer,
    specification: TableSpecification,
    maximum_rows: usize,
    cancellation: &CancellationToken,
    convert: fn(T) -> NativePortRow,
) -> Result<Vec<NativePortRow>, AppError> {
    let bytes = buffer.bytes();
    let count_bytes: [u8; size_of::<u32>()] = bytes
        .get(..size_of::<u32>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_buffer_error(specification, "table entry count is unavailable"))?;
    let count = u32::from_ne_bytes(count_bytes) as usize;
    let row_bytes = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        invalid_buffer_error(specification, "table row byte length overflows usize")
    })?;
    let required = size_of::<u32>()
        .checked_add(row_bytes)
        .ok_or_else(|| invalid_buffer_error(specification, "table byte length overflows usize"))?;
    if required > bytes.len() {
        return Err(invalid_buffer_error(
            specification,
            "entry count exceeds the returned table length",
        ));
    }
    if count > maximum_rows {
        return Err(row_limit_error(specification, count, maximum_rows));
    }

    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation, specification)?;
        }
        let offset =
            size_of::<u32>()
                .checked_add(index.checked_mul(size_of::<T>()).ok_or_else(|| {
                    invalid_buffer_error(specification, "row offset overflows usize")
                })?)
                .ok_or_else(|| invalid_buffer_error(specification, "row offset overflows usize"))?;
        let end = offset
            .checked_add(size_of::<T>())
            .ok_or_else(|| invalid_buffer_error(specification, "row end offset overflows usize"))?;
        let row_bytes = bytes.get(offset..end).ok_or_else(|| {
            invalid_buffer_error(specification, "row extends beyond the returned table")
        })?;
        // Safety: the checked slice contains exactly one complete `T`. The
        // table ABI is asserted above and unaligned reads handle the 4-byte
        // count prefix without assuming stronger alignment.
        let row = unsafe { row_bytes.as_ptr().cast::<T>().read_unaligned() };
        rows.push(convert(row));
    }
    Ok(rows)
}

fn convert_tcp_ipv4(row: MIB_TCPROW_OWNER_PID) -> NativePortRow {
    NativePortRow {
        pid: row.dwOwningPid,
        protocol: PortProtocol::Tcp,
        address_family: AddressFamily::Ipv4,
        local_address: Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).to_string(),
        local_port: decode_port(row.dwLocalPort),
        state: tcp_state(row.dwState),
    }
}

fn convert_tcp_ipv6(row: MIB_TCP6ROW_OWNER_PID) -> NativePortRow {
    NativePortRow {
        pid: row.dwOwningPid,
        protocol: PortProtocol::Tcp,
        address_family: AddressFamily::Ipv6,
        local_address: ipv6_address(row.ucLocalAddr, row.dwLocalScopeId),
        local_port: decode_port(row.dwLocalPort),
        state: tcp_state(row.dwState),
    }
}

fn convert_udp_ipv4(row: MIB_UDPROW_OWNER_PID) -> NativePortRow {
    NativePortRow {
        pid: row.dwOwningPid,
        protocol: PortProtocol::Udp,
        address_family: AddressFamily::Ipv4,
        local_address: Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).to_string(),
        local_port: decode_port(row.dwLocalPort),
        state: FieldValue::Known(PortState::UdpBound),
    }
}

fn convert_udp_ipv6(row: MIB_UDP6ROW_OWNER_PID) -> NativePortRow {
    NativePortRow {
        pid: row.dwOwningPid,
        protocol: PortProtocol::Udp,
        address_family: AddressFamily::Ipv6,
        local_address: ipv6_address(row.ucLocalAddr, row.dwLocalScopeId),
        local_port: decode_port(row.dwLocalPort),
        state: FieldValue::Known(PortState::UdpBound),
    }
}

fn ipv6_address(address: [u8; 16], scope_id: u32) -> String {
    let address = Ipv6Addr::from(address);
    if scope_id == 0 {
        address.to_string()
    } else {
        format!("{address}%{scope_id}")
    }
}

fn decode_port(value: u32) -> u16 {
    // IP Helper documents only the low 16 bits; the high half may be
    // uninitialized. The retained low word is in network byte order.
    u16::from_be(value as u16)
}

fn tcp_state(state: u32) -> FieldValue<PortState> {
    match state {
        2 => FieldValue::Known(PortState::TcpListen),
        5 => FieldValue::Known(PortState::TcpEstablished),
        1..=12 | 100 => FieldValue::Known(PortState::TcpOther),
        _ => FieldValue::Unknown,
    }
}

fn access_limited(specification: TableSpecification, code: u32) -> FieldValue<Vec<NativePortRow>> {
    FieldValue::AccessLimited {
        reason: Some(format!(
            "{}({}):win32:{code}",
            specification.operation(),
            specification.family()
        )),
    }
}

fn ensure_within_limit(
    specification: TableSpecification,
    requested: usize,
) -> Result<(), AppError> {
    if requested <= MAX_TABLE_BUFFER_BYTES {
        Ok(())
    } else {
        Err(buffer_limit_error(specification, requested))
    }
}

fn buffer_limit_error(specification: TableSpecification, requested: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows port table query exceeded its memory limit",
    );
    error.retryable = true;
    add_context(&mut error, specification);
    error
        .details
        .insert("requestedBytes".into(), requested.to_string());
    error
        .details
        .insert("maximumBytes".into(), MAX_TABLE_BUFFER_BYTES.to_string());
    error
}

fn row_limit_error(
    specification: TableSpecification,
    returned_rows: usize,
    remaining_rows: usize,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows port table query exceeded its row limit",
    );
    error.retryable = true;
    add_context(&mut error, specification);
    error
        .details
        .insert("returnedRows".into(), returned_rows.to_string());
    error
        .details
        .insert("maximumRows".into(), MAX_NATIVE_PORT_ROWS.to_string());
    error
        .details
        .insert("remainingRows".into(), remaining_rows.to_string());
    error
}

fn invalid_buffer_error(specification: TableSpecification, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows port table query returned an invalid buffer",
    );
    add_context(&mut error, specification);
    error.details.insert("reason".into(), reason.into());
    error
}

fn win32_error(specification: TableSpecification, code: u32) -> AppError {
    let mut error = AppError::new(ErrorCode::PlatformError, "Windows port table query failed");
    error.retryable = true;
    add_context(&mut error, specification);
    error.details.insert("win32Code".into(), code.to_string());
    error
}

fn check_cancelled(
    cancellation: &CancellationToken,
    specification: TableSpecification,
) -> Result<(), AppError> {
    if cancellation.is_cancelled() {
        let mut error = AppError::new(ErrorCode::Timeout, "Windows port table query was cancelled");
        error.retryable = true;
        add_context(&mut error, specification);
        Err(error)
    } else {
        Ok(())
    }
}

fn add_context(error: &mut AppError, specification: TableSpecification) {
    error
        .details
        .insert("operation".into(), specification.operation().into());
    error
        .details
        .insert("addressFamily".into(), specification.family().into());
}
