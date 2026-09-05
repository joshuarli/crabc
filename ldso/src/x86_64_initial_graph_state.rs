//! Loader-owned identity and transaction state for one x86-64 initial graph.
//!
//! This is deliberately independent of ELF parsing and Linux mapping.  The
//! mapper supplies a stable `(st_dev, st_ino)` identity before it creates a
//! mapping, while this record owns the admitted-object order, `DT_NEEDED`
//! edges, cycle state, and transaction rollback boundary.  Keeping those
//! facts together prevents a repeated dependency from becoming a second map
//! merely because it is reached through a different parent.

#![allow(dead_code)]

pub(crate) const MAX_INITIAL_GRAPH_OBJECTS: usize = 32;
pub(crate) const MAX_INITIAL_GRAPH_NEEDED: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObjectIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectState {
    Vacant,
    Discovering,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectAdmission {
    Existing { index: usize, state: ObjectState },
    New { index: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GraphStateError {
    ObjectCapacity,
    EdgeCapacity,
    InvalidObject,
    ObjectNotDiscovering,
    GraphIncomplete,
    DependencyCycle,
}

/// One dependency-first traversal of the immutable initial graph.
///
/// The main image is the traversal root but is intentionally absent from the
/// returned indices: its lifecycle remains CRT-owned.  Every dependency
/// index appears at most once, even when several parents retain an edge to
/// the same object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DependencyFirstPlan {
    indices: [usize; MAX_INITIAL_GRAPH_OBJECTS - 1],
    count: usize,
}

impl DependencyFirstPlan {
    const fn empty() -> Self {
        Self {
            indices: [0; MAX_INITIAL_GRAPH_OBJECTS - 1],
            count: 0,
        }
    }

    pub(crate) fn indices(&self) -> &[usize] {
        &self.indices[..self.count]
    }

    fn push(&mut self, index: usize) -> Result<(), GraphStateError> {
        let slot = self
            .indices
            .get_mut(self.count)
            .ok_or(GraphStateError::ObjectCapacity)?;
        *slot = index;
        self.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ObjectSlot {
    identity: ObjectIdentity,
    state: ObjectState,
    mapped_by_transaction: bool,
    edges: [usize; MAX_INITIAL_GRAPH_NEEDED],
    edge_count: usize,
}

const EMPTY_IDENTITY: ObjectIdentity = ObjectIdentity {
    device: 0,
    inode: 0,
};

const EMPTY_SLOT: ObjectSlot = ObjectSlot {
    identity: EMPTY_IDENTITY,
    state: ObjectState::Vacant,
    mapped_by_transaction: false,
    edges: [0; MAX_INITIAL_GRAPH_NEEDED],
    edge_count: 0,
};

/// The graph portion of the initial-load transaction.
///
/// Slot zero is the main image. This graph rolls back later admissions;
/// `GeneralInitialLoaderState` separately owns slot zero's provenance and
/// releases a directly mapped main last while retaining a kernel-mapped main.
/// A returned `Existing { Discovering }` is a valid cycle edge,
/// not a request to recurse or map the object again.
pub(crate) struct InitialGraphState {
    slots: [ObjectSlot; MAX_INITIAL_GRAPH_OBJECTS],
    object_count: usize,
}

impl InitialGraphState {
    pub(crate) const fn new(main: ObjectIdentity) -> Self {
        let mut slots = [EMPTY_SLOT; MAX_INITIAL_GRAPH_OBJECTS];
        slots[0] = ObjectSlot {
            identity: main,
            state: ObjectState::Discovering,
            mapped_by_transaction: false,
            edges: [0; MAX_INITIAL_GRAPH_NEEDED],
            edge_count: 0,
        };
        Self {
            slots,
            object_count: 1,
        }
    }

    pub(crate) fn object_count(&self) -> usize {
        self.object_count
    }

    pub(crate) fn identity(&self, index: usize) -> Option<ObjectIdentity> {
        self.slot(index).map(|slot| slot.identity)
    }

    pub(crate) fn state(&self, index: usize) -> Option<ObjectState> {
        self.slot(index).map(|slot| slot.state)
    }

    pub(crate) fn edges(&self, index: usize) -> Option<&[usize]> {
        let slot = self.slot(index)?;
        Some(&slot.edges[..slot.edge_count])
    }

    pub(crate) fn find(&self, identity: ObjectIdentity) -> Option<usize> {
        self.slots[..self.object_count]
            .iter()
            .position(|slot| slot.identity == identity)
    }

    /// Records one identity before the caller starts dependency discovery.
    ///
    /// The mapper must complete its file validation and mapping before this
    /// call.  Once admitted, the slot makes a repeated edge and a cycle share
    /// the same object identity for the rest of the transaction.
    pub(crate) fn admit_mapped(
        &mut self,
        identity: ObjectIdentity,
    ) -> Result<ObjectAdmission, GraphStateError> {
        if let Some(index) = self.find(identity) {
            return Ok(ObjectAdmission::Existing {
                index,
                state: self.slots[index].state,
            });
        }
        if self.object_count == MAX_INITIAL_GRAPH_OBJECTS {
            return Err(GraphStateError::ObjectCapacity);
        }
        let index = self.object_count;
        self.slots[index] = ObjectSlot {
            identity,
            state: ObjectState::Discovering,
            mapped_by_transaction: true,
            edges: [0; MAX_INITIAL_GRAPH_NEEDED],
            edge_count: 0,
        };
        self.object_count += 1;
        Ok(ObjectAdmission::New { index })
    }

    /// Adds one ordered `DT_NEEDED` edge after the child has either been
    /// admitted or found by identity.
    pub(crate) fn attach_needed(
        &mut self,
        parent: usize,
        child: usize,
    ) -> Result<(), GraphStateError> {
        if child >= self.object_count {
            return Err(GraphStateError::InvalidObject);
        }
        let slot = self.slot_mut(parent)?;
        if slot.edge_count == MAX_INITIAL_GRAPH_NEEDED {
            return Err(GraphStateError::EdgeCapacity);
        }
        slot.edges[slot.edge_count] = child;
        slot.edge_count += 1;
        Ok(())
    }

    pub(crate) fn finish_discovery(&mut self, index: usize) -> Result<(), GraphStateError> {
        let slot = self.slot_mut(index)?;
        if slot.state != ObjectState::Discovering {
            return Err(GraphStateError::ObjectNotDiscovering);
        }
        slot.state = ObjectState::Ready;
        Ok(())
    }

    /// Derives the one initial dependency-constructor order from `DT_NEEDED`
    /// edges.
    ///
    /// This is a postorder traversal rooted at the main image.  It is the
    /// narrow rule needed for initial dependency `DT_INIT_ARRAY` dispatch:
    /// children precede parents, repeated identities appear once, and the
    /// executable remains outside the plan.  Discovery is allowed to retain
    /// a cycle so mapping/rollback stays identity-correct; lifecycle dispatch
    /// is stricter and rejects that cycle before any callback can run.
    pub(crate) fn dependency_first_plan(
        &self,
    ) -> Result<DependencyFirstPlan, GraphStateError> {
        if self.object_count == 0
            || self.slots[..self.object_count]
                .iter()
                .any(|slot| slot.state != ObjectState::Ready)
        {
            return Err(GraphStateError::GraphIncomplete);
        }

        let mut marks = [0u8; MAX_INITIAL_GRAPH_OBJECTS];
        let mut plan = DependencyFirstPlan::empty();
        self.plan_dependencies_from(0, &mut marks, &mut plan)?;
        Ok(plan)
    }

    fn plan_dependencies_from(
        &self,
        index: usize,
        marks: &mut [u8; MAX_INITIAL_GRAPH_OBJECTS],
        plan: &mut DependencyFirstPlan,
    ) -> Result<(), GraphStateError> {
        let mark = *marks.get(index).ok_or(GraphStateError::InvalidObject)?;
        match mark {
            1 => return Err(GraphStateError::DependencyCycle),
            2 => return Ok(()),
            0 => {}
            _ => return Err(GraphStateError::InvalidObject),
        }
        let slot = self.slot(index).ok_or(GraphStateError::InvalidObject)?;
        if slot.state != ObjectState::Ready {
            return Err(GraphStateError::GraphIncomplete);
        }
        marks[index] = 1;
        for &child in &slot.edges[..slot.edge_count] {
            self.plan_dependencies_from(child, marks, plan)?;
        }
        marks[index] = 2;
        if index != 0 {
            plan.push(index)?;
        }
        Ok(())
    }

    /// Drops every transaction-created object in reverse map order and keeps
    /// the kernel main image as the sole discovering slot.  The callback owns
    /// the physical `munmap`; it sees only successfully admitted mappings.
    pub(crate) fn rollback_to_main(&mut self, mut unmap: impl FnMut(usize)) {
        for index in (1..self.object_count).rev() {
            if self.slots[index].mapped_by_transaction {
                unmap(index);
            }
            self.slots[index] = EMPTY_SLOT;
        }
        self.object_count = 1;
        self.slots[0].edges = [0; MAX_INITIAL_GRAPH_NEEDED];
        self.slots[0].edge_count = 0;
        self.slots[0].state = ObjectState::Discovering;
    }

    fn slot(&self, index: usize) -> Option<&ObjectSlot> {
        self.slots[..self.object_count].get(index)
    }

    fn slot_mut(&mut self, index: usize) -> Result<&mut ObjectSlot, GraphStateError> {
        self.slots[..self.object_count]
            .get_mut(index)
            .ok_or(GraphStateError::InvalidObject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: ObjectIdentity = ObjectIdentity { device: 1, inode: 1 };
    const LEFT: ObjectIdentity = ObjectIdentity { device: 1, inode: 2 };
    const RIGHT: ObjectIdentity = ObjectIdentity { device: 1, inode: 3 };
    const SHARED: ObjectIdentity = ObjectIdentity { device: 1, inode: 4 };

    #[test]
    fn diamond_reuses_one_identity_and_retains_parent_edges() {
        let mut graph = InitialGraphState::new(MAIN);
        let left = match graph.admit_mapped(LEFT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, left).unwrap();
        let shared = match graph.admit_mapped(SHARED).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(left, shared).unwrap();
        graph.finish_discovery(shared).unwrap();
        graph.finish_discovery(left).unwrap();

        let right = match graph.admit_mapped(RIGHT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, right).unwrap();
        let repeated = graph.admit_mapped(SHARED).unwrap();
        assert_eq!(
            repeated,
            ObjectAdmission::Existing {
                index: shared,
                state: ObjectState::Ready,
            }
        );
        graph.attach_needed(right, shared).unwrap();
        graph.finish_discovery(right).unwrap();
        graph.finish_discovery(0).unwrap();

        assert_eq!(graph.object_count(), 4);
        assert_eq!(graph.edges(0), Some(&[left, right][..]));
        assert_eq!(graph.edges(left), Some(&[shared][..]));
        assert_eq!(graph.edges(right), Some(&[shared][..]));
        assert_eq!(graph.identity(shared), Some(SHARED));
    }

    #[test]
    fn cycle_returns_the_discovering_object_without_remapping_it() {
        let mut graph = InitialGraphState::new(MAIN);
        let left = match graph.admit_mapped(LEFT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, left).unwrap();
        let right = match graph.admit_mapped(RIGHT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(left, right).unwrap();

        assert_eq!(
            graph.admit_mapped(LEFT).unwrap(),
            ObjectAdmission::Existing {
                index: left,
                state: ObjectState::Discovering,
            }
        );
        graph.attach_needed(right, left).unwrap();
        graph.finish_discovery(right).unwrap();
        graph.finish_discovery(left).unwrap();
        graph.finish_discovery(0).unwrap();

        assert_eq!(graph.object_count(), 3);
        assert_eq!(graph.edges(right), Some(&[left][..]));
        assert_eq!(graph.state(left), Some(ObjectState::Ready));
    }

    #[test]
    fn failed_transaction_unmaps_only_new_objects_in_reverse_order() {
        let mut graph = InitialGraphState::new(MAIN);
        let first = match graph.admit_mapped(LEFT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        let second = match graph.admit_mapped(RIGHT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        let mut unmapped = [usize::MAX; 2];
        let mut count = 0;
        graph.rollback_to_main(|index| {
            unmapped[count] = index;
            count += 1;
        });

        assert_eq!(unmapped, [second, first]);
        assert_eq!(graph.object_count(), 1);
        assert_eq!(graph.state(0), Some(ObjectState::Discovering));
        assert_eq!(graph.edges(0), Some(&[][..]));
    }

    #[test]
    fn dependency_first_plan_is_diamond_ordered_and_once_only() {
        let mut graph = InitialGraphState::new(MAIN);
        let left = match graph.admit_mapped(LEFT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        let right = match graph.admit_mapped(RIGHT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        let shared = match graph.admit_mapped(SHARED).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, left).unwrap();
        graph.attach_needed(0, right).unwrap();
        graph.attach_needed(left, shared).unwrap();
        graph.attach_needed(right, shared).unwrap();
        graph.finish_discovery(shared).unwrap();
        graph.finish_discovery(left).unwrap();
        graph.finish_discovery(right).unwrap();
        graph.finish_discovery(0).unwrap();

        assert_eq!(
            graph.dependency_first_plan().unwrap().indices(),
            &[shared, left, right]
        );
    }

    #[test]
    fn dependency_first_plan_rejects_a_ready_cycle_before_dispatch() {
        let mut graph = InitialGraphState::new(MAIN);
        let left = match graph.admit_mapped(LEFT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        let right = match graph.admit_mapped(RIGHT).unwrap() {
            ObjectAdmission::New { index } => index,
            other => panic!("unexpected admission: {other:?}"),
        };
        graph.attach_needed(0, left).unwrap();
        graph.attach_needed(left, right).unwrap();
        graph.attach_needed(right, left).unwrap();
        graph.finish_discovery(right).unwrap();
        graph.finish_discovery(left).unwrap();
        graph.finish_discovery(0).unwrap();

        assert_eq!(
            graph.dependency_first_plan(),
            Err(GraphStateError::DependencyCycle)
        );
    }
}
