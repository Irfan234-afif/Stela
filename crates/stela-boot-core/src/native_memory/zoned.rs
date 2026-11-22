//! The page source the native drivers get: the mount's heap, and a separate
//! reservation below 4 GiB for the 32-bit DMA that heap cannot place.
use super::NativeMemory;
use stela_drivers::bus::dma::memory::{
    CacheAttribute, MemoryError, PageGeometry, PageSource, PinnedPages,
};

/// The first physical address a 32-bit device cannot reach.
pub const DMA32_END: u64 = 1 << 32;

/// The mount's heap (`main`) for every request, and its low zone (`dma32`)
/// for a request below an end at or under [`DMA32_END`] that `main` has no
/// free memory below. On a PC with more than 4 GiB of RAM the firmware puts
/// the heap above 4 GiB, and a passthrough domain's device address is the
/// physical one. A plain allocation and a request with a higher end stay
/// on `main`, so the zone is kept for devices that need it. Each pin goes
/// back to the heap its backing came from.
pub struct Zoned {
    main: &'static NativeMemory,
    dma32: &'static NativeMemory,
}

impl Zoned {
    pub const fn new(main: &'static NativeMemory, dma32: &'static NativeMemory) -> Self {
        Self { main, dma32 }
    }
}

impl PageSource for Zoned {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        // Both heaps return pages of the same base granule.
        self.main.page_geometry()
    }

    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        self.main.allocate(bytes, alignment, attribute)
    }

    fn allocate_below(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
        physical_end_exclusive: u64,
    ) -> Result<PinnedPages, MemoryError> {
        match self
            .main
            .allocate_below(bytes, alignment, attribute, physical_end_exclusive)
        {
            Err(MemoryError::OutOfMemory) if physical_end_exclusive <= DMA32_END => {
                match self
                    .dma32
                    .allocate_below(bytes, alignment, attribute, physical_end_exclusive)
                {
                    // A boot whose firmware had no room for the zone has
                    // none registered; the heap's answer stands.
                    Err(MemoryError::Unavailable) => Err(MemoryError::OutOfMemory),
                    pages => pages,
                }
            }
            pages => pages,
        }
    }
}

#[cfg(test)]
mod tests;
