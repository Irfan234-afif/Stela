use super::*;
use crate::heap::Heap;
use crate::native_memory::PAGE;
use core::{alloc::Layout, ops::Range};

const WB: CacheAttribute = CacheAttribute::WriteBack;
/// Model physical bases: a heap above 4 GiB, one below it, and the zone.
const ABOVE: u64 = 0x2_0000_0000;
const BELOW: u64 = 0x4000_0000;
const ZONE: u64 = 0x1000_0000;

/// A test's own heaps and page sources, which no other test touches.
macro_rules! heaps {
    () => {{
        static MAIN_HEAP: Heap = Heap::new();
        static DMA32_HEAP: Heap = Heap::new();
        static MAIN: NativeMemory = NativeMemory::new(&MAIN_HEAP, |_, _, _, _| Ok(()));
        static DMA32: NativeMemory = NativeMemory::new(&DMA32_HEAP, |_, _, _, _| Ok(()));
        (&MAIN_HEAP, &MAIN, &DMA32_HEAP, &DMA32)
    }};
}

/// Host RAM under one test heap, registered at a model physical base. It
/// outlives every pin the test takes from it.
struct Ram {
    pointer: *mut u8,
    layout: Layout,
    physical: Range<u64>,
}

impl Ram {
    fn register(
        heap: &'static Heap,
        memory: &'static NativeMemory,
        pages: usize,
        physical: u64,
    ) -> Self {
        let layout = Layout::from_size_align(pages * PAGE, PAGE).unwrap();
        // SAFETY: a nonzero layout.
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        // SAFETY: this test's own unused extent, kept until every pin from
        // it ends; the physical base is a label, never dereferenced.
        unsafe {
            heap.initialize(pointer, layout.size());
            memory.initialize(pointer as usize, physical, layout.size(), 0);
        }
        Self {
            pointer,
            layout,
            physical: physical..physical + layout.size() as u64,
        }
    }

    fn holds(&self, pages: &PinnedPages) -> bool {
        let first = pages.physical_pages()[0];
        first >= self.physical.start && first + pages.bytes() as u64 <= self.physical.end
    }
}

impl Drop for Ram {
    fn drop(&mut self) {
        // SAFETY: the allocation above, with every pin from it ended.
        unsafe { std::alloc::dealloc(self.pointer, self.layout) };
    }
}

#[test]
fn a_low_request_takes_the_heap_while_it_has_memory_below_4_gib() {
    let (main_heap, main, dma32_heap, dma32) = heaps!();
    let main_ram = Ram::register(main_heap, main, 32, BELOW);
    let _zone_ram = Ram::register(dma32_heap, dma32, 32, ZONE);
    let zoned = Zoned::new(main, dma32);
    let pages = zoned.allocate_below(2 * PAGE, PAGE, WB, DMA32_END).unwrap();
    assert!(main_ram.holds(&pages));
    assert_eq!(main_heap.usage().live, 2 * PAGE);
    assert_eq!(dma32_heap.usage().live, 0);
    drop(pages);
    assert_eq!(main_heap.usage().live, 0);
    assert_eq!(dma32_heap.usage().live, 0);
}

#[test]
fn a_low_request_the_heap_cannot_place_takes_the_zone_and_goes_back_to_it() {
    let (main_heap, main, dma32_heap, dma32) = heaps!();
    let main_ram = Ram::register(main_heap, main, 32, ABOVE);
    let zone_ram = Ram::register(dma32_heap, dma32, 32, ZONE);
    let zoned = Zoned::new(main, dma32);
    let rings = zoned.allocate_below(3 * PAGE, PAGE, WB, DMA32_END).unwrap();
    assert!(zone_ram.holds(&rings));
    assert_eq!(rings.bytes(), 3 * PAGE);
    assert_eq!(dma32_heap.usage().live, 3 * PAGE);
    assert_eq!(main_heap.usage().live, 0);
    // The end is kept inside the zone too.
    let end = ZONE + 8 * PAGE as u64;
    let near = zoned.allocate_below(PAGE, PAGE, WB, end).unwrap();
    assert!(near.physical_pages()[0] + PAGE as u64 <= end);
    assert!(matches!(
        zoned.allocate_below(PAGE, PAGE, WB, ZONE),
        Err(MemoryError::OutOfMemory)
    ));
    // A higher end the heap cannot meet is refused, not given the zone.
    assert!(matches!(
        zoned.allocate_below(PAGE, PAGE, WB, ABOVE),
        Err(MemoryError::OutOfMemory)
    ));
    // Refusals other than room are the heap's, unretried.
    assert!(matches!(
        zoned.allocate_below(PAGE, 3, WB, DMA32_END),
        Err(MemoryError::InvalidAlignment)
    ));
    assert!(matches!(
        zoned.allocate_below(PAGE, PAGE, CacheAttribute::Uncached, DMA32_END),
        Err(MemoryError::CacheAttributeUnavailable)
    ));
    assert_eq!(dma32_heap.usage().live, 4 * PAGE);
    let plain = zoned.allocate(PAGE, PAGE, WB).unwrap();
    assert!(main_ram.holds(&plain));
    assert_eq!(main_heap.usage().live, PAGE);
    assert_eq!(dma32_heap.usage().live, 4 * PAGE);
    // A clone keeps the pages until the last owner ends.
    let kept = rings.clone();
    drop(rings);
    assert_eq!(dma32_heap.usage().live, 4 * PAGE);
    drop(kept);
    drop(near);
    assert_eq!(dma32_heap.usage().live, 0);
    assert_eq!(main_heap.usage().live, PAGE);
    drop(plain);
    assert_eq!(main_heap.usage().live, 0);
}

#[test]
fn the_heap_serves_low_requests_again_once_its_memory_below_4_gib_is_free() {
    let (main_heap, main, dma32_heap, dma32) = heaps!();
    // Four pages below 4 GiB: the heap's header and three payload pages.
    let main_ram = Ram::register(main_heap, main, 32, DMA32_END - 4 * PAGE as u64);
    let zone_ram = Ram::register(dma32_heap, dma32, 32, ZONE);
    let zoned = Zoned::new(main, dma32);
    let first = zoned.allocate_below(3 * PAGE, PAGE, WB, DMA32_END).unwrap();
    assert!(main_ram.holds(&first));
    assert_eq!(first.physical_pages()[2] + PAGE as u64, DMA32_END);
    let second = zoned.allocate_below(PAGE, PAGE, WB, DMA32_END).unwrap();
    assert!(zone_ram.holds(&second));
    assert_eq!(dma32_heap.usage().live, PAGE);
    drop(first);
    let third = zoned.allocate_below(PAGE, PAGE, WB, DMA32_END).unwrap();
    assert!(main_ram.holds(&third));
    assert!(third.physical_pages()[0] < DMA32_END);
    assert_eq!(main_heap.usage().live, PAGE);
    assert_eq!(dma32_heap.usage().live, PAGE);
    drop(second);
    drop(third);
    assert_eq!(main_heap.usage().live, 0);
    assert_eq!(dma32_heap.usage().live, 0);
}

#[test]
fn an_exhausted_zone_is_out_of_memory_and_plain_allocations_never_use_it() {
    let (main_heap, main, dma32_heap, dma32) = heaps!();
    let main_ram = Ram::register(main_heap, main, 32, ABOVE);
    let zone_ram = Ram::register(dma32_heap, dma32, 8, ZONE);
    let zoned = Zoned::new(main, dma32);
    let mut held = alloc::vec::Vec::new();
    let refusal = loop {
        match zoned.allocate_below(PAGE, PAGE, WB, DMA32_END) {
            Ok(pages) => held.push(pages),
            Err(error) => break error,
        }
    };
    assert_eq!(refusal, MemoryError::OutOfMemory);
    assert!(!held.is_empty() && held.iter().all(|pages| zone_ram.holds(pages)));
    let full = dma32_heap.usage();
    assert_eq!(full.live, held.len() * PAGE);
    assert!(matches!(
        zoned.allocate_below(PAGE, PAGE, WB, DMA32_END),
        Err(MemoryError::OutOfMemory)
    ));
    assert_eq!(main_heap.usage().live, 0);
    // The heap still serves plain allocations, and one it has no room for
    // is refused without the zone, which had room for none anyway.
    let plain = zoned.allocate(PAGE, PAGE, WB).unwrap();
    assert!(main_ram.holds(&plain));
    drop(held.pop());
    assert!(matches!(
        zoned.allocate(32 * PAGE, PAGE, WB),
        Err(MemoryError::OutOfMemory)
    ));
    assert_eq!(dma32_heap.usage().live, held.len() * PAGE);
    assert_eq!(main_heap.usage().live, PAGE);
    drop(held);
    drop(plain);
    assert_eq!(dma32_heap.usage().live, 0);
    assert_eq!(main_heap.usage().live, 0);
    assert_eq!(dma32_heap.usage().carved, 0);
}

#[test]
fn without_a_zone_a_low_request_the_heap_cannot_place_is_out_of_memory() {
    let (main_heap, main, _, dma32) = heaps!();
    let main_ram = Ram::register(main_heap, main, 32, ABOVE);
    let zoned = Zoned::new(main, dma32);
    assert_eq!(zoned.page_geometry(), main.page_geometry());
    assert!(matches!(
        zoned.allocate_below(PAGE, PAGE, WB, DMA32_END),
        Err(MemoryError::OutOfMemory)
    ));
    let plain = zoned.allocate(PAGE, PAGE, WB).unwrap();
    assert!(main_ram.holds(&plain));
    drop(plain);
    assert_eq!(main_heap.usage().live, 0);
}
