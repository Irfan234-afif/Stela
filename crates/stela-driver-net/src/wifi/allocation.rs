//! Common native DMA backing construction for Wi-Fi queue owners.
//!
//! Publication, completion and uncertain retirement stay with the vendor
//! queue. A WB mapping alone does not establish hardware coherence: each
//! installer must check the requester and its NoSnoop/ATS policy.
use crate::bus::dma::{
    mapping::{Direction, DmaDomain, DmaError, DmaMapping, DomainKind},
    memory::{CacheAttribute, CpuMapping, MemoryError, PageSource, PinnedPages},
};
use alloc::sync::Arc;

/// The first physical address a 32-bit device cannot reach.
const DMA32_END: u64 = 1 << 32;

/// Preserve the native allocation, CPU mapping and device mapping order.
/// Each vendor keeps its existing typed error conversions and queue lifetime.
///
/// Without a remapper the device address is the physical one, so on a
/// passthrough domain the pages themselves are taken below 4 GiB, as tg3
/// takes them; a machine with more RAM than that would otherwise hand out
/// pages the mapping then refuses with `AddressLimit`. A provider that
/// cannot select by address falls back to an ordinary allocation, which the
/// mapping's limit still checks.
pub(super) fn allocate_32bit<E>(
    source: &dyn PageSource,
    domain: Arc<dyn DmaDomain>,
    bytes: usize,
    direction: Direction,
) -> Result<(CpuMapping, DmaMapping), E>
where
    E: From<MemoryError> + From<DmaError>,
{
    let pages = pin(source, domain.kind(), bytes)?;
    let cpu = pages.cpu_mapping(CacheAttribute::WriteBack)?;
    let dma = DmaMapping::map(domain, pages, direction, u32::MAX.into())?;
    Ok((cpu, dma))
}

/// The pages for a 32-bit device on a domain of `kind`: below 4 GiB on a
/// passthrough domain when the provider can select by address.
fn pin(
    source: &dyn PageSource,
    kind: DomainKind,
    bytes: usize,
) -> Result<PinnedPages, MemoryError> {
    if kind == DomainKind::Passthrough {
        match source.allocate_below(bytes, 4096, CacheAttribute::WriteBack, DMA32_END) {
            Err(MemoryError::Unavailable) => {}
            pages => return pages,
        }
    }
    source.allocate(bytes, 4096, CacheAttribute::WriteBack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    /// A provider that records each request and refuses it with `answer`,
    /// or with `Unavailable` for a selection by address it cannot make.
    struct Recorder {
        selects: bool,
        answer: MemoryError,
        calls: RefCell<alloc::vec::Vec<Option<u64>>>,
    }

    impl PageSource for Recorder {
        fn allocate(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            self.calls.borrow_mut().push(None);
            Err(self.answer)
        }
        fn allocate_below(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
            end: u64,
        ) -> Result<PinnedPages, MemoryError> {
            self.calls.borrow_mut().push(Some(end));
            Err(if self.selects {
                self.answer
            } else {
                MemoryError::Unavailable
            })
        }
    }

    fn calls(selects: bool, kind: DomainKind) -> alloc::vec::Vec<Option<u64>> {
        let source = Recorder {
            selects,
            answer: MemoryError::OutOfMemory,
            calls: RefCell::default(),
        };
        assert!(pin(&source, kind, 4096).is_err());
        source.calls.into_inner()
    }

    #[test]
    fn passthrough_pages_are_taken_below_4_gib_and_isolated_ones_anywhere() {
        // Below 4 GiB on passthrough; an exhausted low zone is not retried
        // anywhere else, since the mapping would refuse those pages.
        assert_eq!(calls(true, DomainKind::Passthrough), [Some(1 << 32)]);
        // A provider that cannot select falls back to an ordinary request.
        assert_eq!(calls(false, DomainKind::Passthrough), [Some(1 << 32), None]);
        // An IOMMU domain places the IOVA itself.
        assert_eq!(calls(true, DomainKind::Isolated), [None]);
    }
}
