//! Private loader-owned state for the x86 RuntimeV1 initial TLS population.
//!
//! This is deliberately an initial-only registry, not a partial dynamic TLS
//! implementation. It gives every admitted initial `PT_TLS` image a stable,
//! one-based module ID in loader order and seals generation one before the
//! libc handoff. A later runtime `PT_TLS` request is rejected without changing
//! the IDs, generation, or fixed DTV geometry: adding capacity, refreshing
//! existing threads, initializing new threads, and reclaiming old DTV storage
//! are one inseparable future protocol.

use core::num::{NonZeroU64, NonZeroUsize};

/// One-based loader-owned TLS module ID.
///
/// Zero is reserved by the ELF TLS ABI and cannot be represented by this
/// type. The raw integer reaches relocation/DTV code only at the exact local
/// boundary that writes an ELF ABI value.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TlsModuleId(NonZeroUsize);

impl TlsModuleId {
    fn from_one_based(value: usize) -> Option<Self> {
        NonZeroUsize::new(value).map(Self)
    }

    /// Returns the ELF one-based module number.
    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }
}

/// The immutable generation for the completed initial TLS population.
///
/// This type intentionally has no increment operation. A general loader may
/// introduce a later monotonic generation type only with the full DTV-growth
/// and thread-refresh protocol; this initial foundation must not grow by
/// raising a fixed bound or by incrementing a counter alone.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InitialTlsGeneration(NonZeroU64);

impl InitialTlsGeneration {
    /// The one initial population has generation one.
    pub(crate) const fn initial() -> Self {
        Self(NonZeroU64::MIN)
    }

    /// Returns the wire value used by the private RuntimeV1 descriptor.
    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }
}

/// State transition for the bounded initial population.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryPhase {
    /// Initial loader discovery may still assign a module ID.
    Planning,
    /// Initial IDs and generation one are immutable for this process image.
    Sealed,
}

/// Reasons an initial population cannot be represented by this registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitialTlsRegistryError {
    /// The object lies outside the loader's bounded initial object set.
    ObjectIndexOutOfRange,
    /// The object already owns a stable initial module ID.
    ObjectAlreadyAssigned,
    /// The fixed initial DTV cannot represent another initial TLS module.
    InitialModuleCapacityExhausted,
    /// The initial population is immutable after its handoff boundary.
    RegistrySealed,
}

/// The explicit result for a runtime `PT_TLS` / DTV-growth request.
///
/// The absence of a growth protocol is a loader decision, not an invitation
/// for libc to allocate a DTV or install a replacement thread pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeTlsGrowthError {
    /// Registry expansion, current-thread refresh, new-thread initialization,
    /// and safe old-DTV reclamation have not been implemented as one protocol.
    DtvGrowthProtocolUnavailable,
}

/// A typed, bounded initial TLS registry owned by the x86 loader.
///
/// `OBJECT_CAPACITY` is the known initial graph bound and `MODULE_CAPACITY`
/// is the number of nonzero DTV slots available to its initial population.
/// The registry records object-index-to-module-ID ownership, rather than
/// assuming object indices are module IDs; TLS-free objects consume neither.
pub(crate) struct InitialTlsRegistry<const OBJECT_CAPACITY: usize, const MODULE_CAPACITY: usize> {
    module_ids: [Option<TlsModuleId>; OBJECT_CAPACITY],
    module_count: usize,
    generation: InitialTlsGeneration,
    phase: RegistryPhase,
}

impl<const OBJECT_CAPACITY: usize, const MODULE_CAPACITY: usize>
    InitialTlsRegistry<OBJECT_CAPACITY, MODULE_CAPACITY>
{
    /// Starts an empty generation-one initial population.
    pub(crate) const fn new() -> Self {
        Self {
            module_ids: [None; OBJECT_CAPACITY],
            module_count: 0,
            generation: InitialTlsGeneration::initial(),
            phase: RegistryPhase::Planning,
        }
    }

    /// Assigns the next stable one-based ID to one initial TLS-bearing object.
    ///
    /// Callers must have already validated that the object has a usable
    /// `PT_TLS` image. TLS-free objects are deliberately not entered here.
    pub(crate) fn assign_initial(
        &mut self,
        object_index: usize,
    ) -> Result<TlsModuleId, InitialTlsRegistryError> {
        if self.phase != RegistryPhase::Planning {
            return Err(InitialTlsRegistryError::RegistrySealed);
        }
        let slot = self
            .module_ids
            .get_mut(object_index)
            .ok_or(InitialTlsRegistryError::ObjectIndexOutOfRange)?;
        if slot.is_some() {
            return Err(InitialTlsRegistryError::ObjectAlreadyAssigned);
        }
        if self.module_count == MODULE_CAPACITY {
            return Err(InitialTlsRegistryError::InitialModuleCapacityExhausted);
        }
        let next = self
            .module_count
            .checked_add(1)
            .ok_or(InitialTlsRegistryError::InitialModuleCapacityExhausted)?;
        let module_id = TlsModuleId::from_one_based(next)
            .ok_or(InitialTlsRegistryError::InitialModuleCapacityExhausted)?;
        self.module_count = next;
        *slot = Some(module_id);
        Ok(module_id)
    }

    /// Seals the initial module-ID population at generation one.
    pub(crate) fn seal(&mut self) -> Result<(), InitialTlsRegistryError> {
        if self.phase != RegistryPhase::Planning {
            return Err(InitialTlsRegistryError::RegistrySealed);
        }
        self.phase = RegistryPhase::Sealed;
        Ok(())
    }

    /// Returns this object's initial module ID, if it has `PT_TLS`.
    pub(crate) const fn module_id(&self, object_index: usize) -> Option<TlsModuleId> {
        if object_index >= OBJECT_CAPACITY {
            return None;
        }
        self.module_ids[object_index]
    }

    /// Returns the completed initial TLS module count.
    pub(crate) const fn module_count(&self) -> usize {
        self.module_count
    }

    /// Returns the initial generation carried over the private RuntimeV1 wire.
    pub(crate) const fn generation(&self) -> InitialTlsGeneration {
        self.generation
    }

    /// Returns the current immutable lifecycle phase.
    pub(crate) const fn phase(&self) -> RegistryPhase {
        self.phase
    }

    /// Explicitly rejects a runtime TLS module before any registry/DTV change.
    ///
    /// The object index is intentionally ignored: accepting it would require
    /// mapping, relocation, constructor ordering, module-ID publication,
    /// current-thread refresh, new-thread materialization, and safe old-DTV
    /// reclamation. Those operations must arrive as one reviewed protocol.
    pub(crate) fn reject_runtime_tls_growth(
        &self,
        _object_index: usize,
    ) -> Result<TlsModuleId, RuntimeTlsGrowthError> {
        Err(RuntimeTlsGrowthError::DtvGrowthProtocolUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_ids_are_one_based_stable_and_skip_tls_free_object_indices() {
        let mut registry = InitialTlsRegistry::<4, 3>::new();
        let first = registry.assign_initial(1).unwrap();
        let second = registry.assign_initial(3).unwrap();

        assert_eq!(first.get(), 1);
        assert_eq!(second.get(), 2);
        assert_eq!(registry.module_id(0), None);
        assert_eq!(registry.module_id(1), Some(first));
        assert_eq!(registry.module_id(2), None);
        assert_eq!(registry.module_id(3), Some(second));
        assert_eq!(registry.module_count(), 2);
        assert_eq!(registry.generation().get(), 1);
        registry.seal().unwrap();
        assert_eq!(registry.phase(), RegistryPhase::Sealed);
        assert_eq!(
            registry.assign_initial(2),
            Err(InitialTlsRegistryError::RegistrySealed)
        );
    }

    #[test]
    fn runtime_tls_growth_rejection_does_not_mutate_the_sealed_registry() {
        let mut registry = InitialTlsRegistry::<4, 3>::new();
        let initial = registry.assign_initial(2).unwrap();
        registry.seal().unwrap();
        let generation = registry.generation();
        let count = registry.module_count();

        assert_eq!(
            registry.reject_runtime_tls_growth(3),
            Err(RuntimeTlsGrowthError::DtvGrowthProtocolUnavailable)
        );
        assert_eq!(registry.phase(), RegistryPhase::Sealed);
        assert_eq!(registry.generation(), generation);
        assert_eq!(registry.module_count(), count);
        assert_eq!(registry.module_id(2), Some(initial));
        assert_eq!(registry.module_id(3), None);
    }

    #[test]
    fn initial_capacity_and_duplicate_ids_fail_before_seal() {
        let mut registry = InitialTlsRegistry::<2, 1>::new();
        registry.assign_initial(0).unwrap();
        assert_eq!(
            registry.assign_initial(0),
            Err(InitialTlsRegistryError::ObjectAlreadyAssigned)
        );
        assert_eq!(
            registry.assign_initial(1),
            Err(InitialTlsRegistryError::InitialModuleCapacityExhausted)
        );
        assert_eq!(
            registry.assign_initial(2),
            Err(InitialTlsRegistryError::ObjectIndexOutOfRange)
        );
    }
}
