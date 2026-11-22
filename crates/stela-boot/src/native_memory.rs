//! The mount's native page source over its heap, and the Linux page catalog
//! bound to it. The source itself is `stela_boot_core::native_memory`.
use crate::handoff::Region;
use core::ptr::NonNull;
use stela_boot_core::heap::Heap;
use stela_boot_core::native_memory::{NativeMemory, PAGE, Registration, Zoned};
use stela_drivers::bus::dma::memory::{CacheAttribute, MemoryError, PageSource, PinnedPages};

pub(crate) mod cache;

pub static SOURCE: NativeMemory = NativeMemory::new(&crate::ALLOCATOR, cache::verify_writeback);

static AMD_TABLE_HEAP: Heap = Heap::new();
pub(crate) static AMD_TABLES: NativeMemory =
    NativeMemory::new(&AMD_TABLE_HEAP, cache::verify_writeback);

static DMA32_HEAP: Heap = Heap::new();
/// The low zone: firmware RAM below 4 GiB the loader reserved for 32-bit
/// device DMA ([`reserve_dma32`]).
static DMA32: NativeMemory = NativeMemory::new(&DMA32_HEAP, cache::verify_writeback);

/// The native drivers' page source (`NativeServices::pages`): the heap, and
/// the low zone for 32-bit DMA when the heap has no free memory below 4 GiB.
/// A PC with more than 4 GiB of RAM gets its heap above 4 GiB, and with no
/// IOMMU translating, or AMD-Vi left off for the firmware's display, a
/// device's address is the physical one.
pub static DRIVER_PAGES: Zoned = Zoned::new(&SOURCE, &DMA32);

/// The low zone's sizes, largest first, for the first one the firmware has
/// room for. An RTL8852BE's rings take about 8 MiB: 512 receive buffers of
/// three pages, each with the zone heap's page of bookkeeping before it,
/// plus their descriptor pools and command buffers. The rest is for the
/// other Wi-Fi drivers' 32-bit rings.
const DMA32_SIZES: [usize; 2] = [32 << 20, 16 << 20];

/// Reserve the low zone, before ExitBootServices, as LOADER_DATA below
/// 4 GiB: the final map then leaves it out of guest RAM, and the physmap,
/// which maps all of `ram`, keeps it mapped write-back in every native
/// root. Without room for the smallest size the boot has no zone, and
/// 32-bit DMA gets only the heap's memory below 4 GiB.
pub(crate) fn reserve_dma32(ram: &[(usize, usize)]) -> Region {
    use uefi::boot::{self, AllocateType, MemoryType};
    for bytes in DMA32_SIZES {
        let Ok(allocation) = boot::allocate_pages(
            AllocateType::MaxAddress(u32::MAX.into()),
            MemoryType::LOADER_DATA,
            bytes / PAGE,
        ) else {
            continue;
        };
        let region = Region {
            physical: allocation.as_ptr() as u64,
            bytes: bytes as u64,
        };
        let end = region.physical + region.bytes;
        if !ram
            .iter()
            .any(|&(start, top)| start as u64 <= region.physical && end <= top as u64)
        {
            // Kept, and so still out of guest RAM, but no driver reaches it.
            crate::output::arguments(format_args!(
                "HOST DMA32 pool withheld: {:#x}-{end:#x} lies outside the physmap's RAM\n",
                region.physical
            ));
            return Region::default();
        }
        crate::output::arguments(format_args!(
            "HOST DMA32 pool={}M at {:#x}\n",
            bytes >> 20,
            region.physical
        ));
        return region;
    }
    crate::output::arguments(format_args!(
        "HOST DMA32 pool unavailable: the firmware has no {}M below 4 GiB, so 32-bit DMA gets only the heap's memory there\n",
        DMA32_SIZES[DMA32_SIZES.len() - 1] >> 20
    ));
    Region::default()
}

/// Register a loader reservation as the separate page source `memory` over
/// `heap`, its only allocator. An empty region leaves it unregistered.
///
/// # Safety
/// `memory` was made over `heap`, and neither is registered yet. The
/// loader's exclusive LOADER_DATA reservation stays mapped in every native
/// root and out of guest RAM. The heap is registered (`initialize`), so its
/// table offset reads the roots. Call once on the BSP, before any user.
unsafe fn initialize_reserved(
    heap: &Heap,
    memory: &NativeMemory,
    region: Region,
) -> Result<(), MemoryError> {
    if region.bytes == 0 {
        return Ok(());
    }
    let bytes = usize::try_from(region.bytes).map_err(|_| MemoryError::InvalidSize)?;
    let cpu = crate::layout::physical(region.physical);
    // SAFETY: the caller retains this reservation and all shared mappings.
    unsafe { qualify_reserved_writeback(cpu, region.physical, bytes) }?;
    // SAFETY: unused firmware-owned RAM; `heap` is its only owner.
    unsafe {
        heap.initialize(cpu as *mut u8, bytes);
        memory.initialize(
            cpu as usize,
            region.physical,
            bytes,
            crate::layout::physical(0),
        );
    }
    Ok(())
}

/// Register the separate low physical memory reserved for AMD-Vi tables.
///
/// # Safety
/// The loader's exclusive LOADER_DATA reservation remains mapped in every
/// native root, outside the guest and driver DMA ranges. Call once on the BSP
/// before remapper startup.
pub(crate) unsafe fn initialize_amd_tables(region: Region) -> Result<(), MemoryError> {
    // SAFETY: the caller's contract, for the AMD table heap's own source.
    unsafe { initialize_reserved(&AMD_TABLE_HEAP, &AMD_TABLES, region) }
}

/// Register the low zone [`reserve_dma32`] reserved, which [`DRIVER_PAGES`]
/// falls back to.
///
/// # Safety
/// The loader's exclusive LOADER_DATA reservation remains mapped in every
/// native root and out of guest RAM, and the heap is registered. Call once
/// on the BSP, before any driver starts.
pub(crate) unsafe fn initialize_dma32(region: Region) -> Result<(), MemoryError> {
    // SAFETY: the caller's contract, for the low zone's own source.
    unsafe { initialize_reserved(&DMA32_HEAP, &DMA32, region) }
}

/// The low zone's physical extent, once registered: device DMA reaches it
/// as it reaches the heap.
pub(crate) fn dma32() -> Option<core::ops::Range<u64>> {
    let registration = DMA32.registration();
    (registration.bytes != 0)
        .then(|| registration.physical..registration.physical + registration.bytes as u64)
}

/// Register the heap's CPU/physical mapping (`NativeMemory::initialize`).
///
/// # Safety
/// As `NativeMemory::initialize`, for the mount's heap.
pub unsafe fn initialize(cpu: usize, physical: u64, bytes: usize, table_offset: u64) {
    // SAFETY: the caller's contract.
    unsafe { SOURCE.initialize(cpu, physical, bytes, table_offset) }
}

/// Keeps the same boot heap generation registered through every consumer.
pub(crate) struct HeapPin {
    registration: Registration,
}

impl HeapPin {
    pub(crate) fn registration(&self) -> Registration {
        self.registration
    }
}

impl Drop for HeapPin {
    fn drop(&mut self) {
        SOURCE.release_catalog();
    }
}

/// Retain the currently registered physical heap and prevent a new generation.
///
/// # Safety
/// Caller owns the original heap/root lifetime and excludes registration
/// changes until the pin is acquired. Retiring the last pin is process-only.
pub(crate) unsafe fn pin_heap() -> Result<HeapPin, MemoryError> {
    let registration = SOURCE.registration();
    if registration.generation == 0 || registration.bytes == 0 {
        return Err(MemoryError::Unavailable);
    }
    SOURCE.retain_catalog()?;
    Ok(HeapPin { registration })
}

pub struct LinuxPages {
    heap: HeapPin,
}

// SAFETY: initialize registered the heap and its WB mapping. The catalog
// count prevents retargeting the generation; each allocation goes through the
// zeroed page source and keeps its backing until the last drop. Unsupported
// flags and contexts are refused before any heap or cache work.
unsafe impl stela_linux::pages::Provider for LinuxPages {
    fn validate(&self, request: stela_linux::pages::Request) -> Result<(), MemoryError> {
        // The pinned heap never sleeps or reclaims, so a request that may
        // not block (TTM's GFP_DMA32 page, say) gets what it asked for. Only
        // atomic context, where the heap's lock could be held, is refused.
        if SOURCE.registration().generation != self.heap.registration().generation
            || request.atomic
            || !(request.basic_ram() || request.reclaimable_ram())
        {
            return Err(MemoryError::Unavailable);
        }
        request.bytes().ok_or(MemoryError::InvalidSize)?;
        Ok(())
    }

    fn allocate(&self, request: stela_linux::pages::Request) -> Result<PinnedPages, MemoryError> {
        self.validate(request)?;
        let bytes = request.bytes().ok_or(MemoryError::InvalidSize)?;
        // The same pinned WB heap supplies Linux's unmovable fallback for
        // reclaimable-class requests. Cache accounting keeps the original class.
        SOURCE.allocate(bytes, bytes, CacheAttribute::WriteBack)
    }
}

/// Bind the registered heap to Linux's native page service.
///
/// # Safety
/// Process or deferred-work context excludes migration, root and cache
/// writers and native IRQ reentry for registration, use and retirement. The
/// heap and its mapping stay registered through every pin and any quarantined
/// catalog; the caller retires the catalog before re-registering the heap.
pub unsafe fn linux_pages()
-> Result<stela_linux::pages::Catalog<LinuxPages>, stela_linux::pages::Error> {
    // SAFETY: the caller's contract.
    let (provider, reservation) = unsafe { linux_page_source() }?;
    // SAFETY: the provider holds the catalog count for this generation.
    unsafe { stela_linux::pages::Catalog::register(provider, reservation) }
}

/// The heap generation and extent for one composed catalog. Returning the
/// reservation allocates nothing.
///
/// # Safety
/// As `linux_pages`.
pub(crate) unsafe fn linux_page_source()
-> Result<(LinuxPages, stela_linux::pages::Reservation), stela_linux::pages::Error> {
    use stela_linux::pages::{Error, Reservation};
    // SAFETY: the original catalog source owns this heap/root lifetime.
    let heap = unsafe { pin_heap() }.map_err(|error| match error {
        MemoryError::Unavailable => Error::InvalidReservation,
        _ => Error::OutOfMemory,
    })?;
    let registration = heap.registration();
    let cpu = NonNull::new(registration.cpu as *mut u8).ok_or(Error::InvalidReservation)?;
    // SAFETY: the registration records this mapping of the heap's RAM.
    let reservation =
        unsafe { Reservation::new(registration.physical, cpu, registration.bytes / PAGE)? };
    let provider = LinuxPages { heap };
    Ok((provider, reservation))
}

/// Check that a loader reservation is mapped write-back, with the decoder
/// native pages use. This allocates nothing and adds no alias.
///
/// # Safety
/// The reservation and its CPU mapping last for the boot; root, cache
/// controls and physical ownership do not change during the check.
pub(crate) unsafe fn qualify_reserved_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
) -> Result<(), MemoryError> {
    cache::verify_writeback(cpu, physical, bytes, SOURCE.table_offset())
}

/// Exercise the registered mapping and allocator through the Linux page
/// catalog and the page source. Called by the mount's host check.
pub fn verify() -> Result<(), MemoryError> {
    // SAFETY: the host check runs in process context, with root and cache
    // writers excluded.
    let mut catalog = unsafe { linux_pages() }.map_err(|_| MemoryError::Unavailable)?;
    catalog.verify().map_err(|error| {
        crate::output::arguments(format_args!("CHECK Linux page catalog FAIL {error:?}\n"));
        MemoryError::InvalidPageList
    })?;
    catalog.try_retire().map_err(|_| MemoryError::Unavailable)?;
    SOURCE.verify()
}
