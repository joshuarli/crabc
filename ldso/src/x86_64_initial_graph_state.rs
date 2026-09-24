//! Loader-owned identity and transaction state for one x86-64 initial graph.
//!
//! This is deliberately independent of ELF parsing and image mapping.  The
//! mapper supplies a stable `(st_dev, st_ino)` identity before it creates a
//! mapping, while this record owns the admitted-object order, `DT_NEEDED`
//! edges, cycle state, and transaction rollback boundary.  Keeping those
//! facts together prevents a repeated dependency from becoming a second map
//! merely because it is reached through a different parent.

#![allow(dead_code)]

use super::x86_64_runtime_memory::LoaderVec;

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

/// The private source-root graphs keep their original admission bounds as
/// part of their frozen negative evidence. The installed runtime has none.
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
const SOURCE_ROOT_MAX_OBJECTS: usize = 32;
#[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
const SOURCE_ROOT_MAX_NEEDED: usize = 16;

/// Graph failures. In the installed runtime the two capacity errors mean the
/// kernel refused the loader mapping that would hold another object or edge:
/// its graph has no fixed object or `DT_NEEDED` bound, as musl's loader has
/// none. Private source roots also report their retained admission bounds.
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
pub(crate) struct DependencyFirstPlan {
    indices: LoaderVec<usize>,
}

impl DependencyFirstPlan {
    pub(crate) fn indices(&self) -> &[usize] {
        &self.indices
    }
}

impl core::fmt::Debug for DependencyFirstPlan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("DependencyFirstPlan").field("indices", &self.indices()).finish()
    }
}

impl PartialEq for DependencyFirstPlan {
    fn eq(&self, other: &Self) -> bool {
        self.indices() == other.indices()
    }
}

impl Eq for DependencyFirstPlan {}

/// One admitted object. Its ordered `DT_NEEDED` edges are the window
/// `edge_start..edge_start + edge_count` of the graph's shared edge store.
#[derive(Clone, Copy)]
struct ObjectSlot {
    identity: ObjectIdentity,
    state: ObjectState,
    mapped_by_transaction: bool,
    edge_start: usize,
    edge_count: usize,
}

const MARK_UNVISITED: u8 = 0;
const MARK_ACTIVE: u8 = 1;
const MARK_DONE: u8 = 2;

/// The graph portion of the initial-load transaction.
///
/// Slot zero is the main image. This graph rolls back later admissions;
/// `GeneralInitialLoaderState` separately owns slot zero's provenance and
/// releases a directly mapped main last while retaining a kernel-mapped main.
/// A returned `Existing { Discovering }` is a valid cycle edge,
/// not a request to recurse or map the object again.
///
/// Objects after main and every edge live in loader mappings that grow with
/// the graph, so neither the object count nor an object's `DT_NEEDED` count
/// is bounded by a table size.
pub(crate) struct InitialGraphState {
    main: ObjectSlot,
    dependencies: LoaderVec<ObjectSlot>,
    edges: LoaderVec<usize>,
}

impl InitialGraphState {
    pub(crate) const fn new(main: ObjectIdentity) -> Self {
        Self {
            main: ObjectSlot {
                identity: main,
                state: ObjectState::Discovering,
                mapped_by_transaction: false,
                edge_start: 0,
                edge_count: 0,
            },
            dependencies: LoaderVec::new(),
            edges: LoaderVec::new(),
        }
    }

    pub(crate) fn object_count(&self) -> usize {
        1 + self.dependencies.len()
    }

    pub(crate) fn identity(&self, index: usize) -> Option<ObjectIdentity> {
        self.slot(index).map(|slot| slot.identity)
    }

    pub(crate) fn state(&self, index: usize) -> Option<ObjectState> {
        self.slot(index).map(|slot| slot.state)
    }

    pub(crate) fn edges(&self, index: usize) -> Option<&[usize]> {
        let slot = self.slot(index)?;
        self.edges.get(slot.edge_start..slot.edge_start + slot.edge_count)
    }

    pub(crate) fn find(&self, identity: ObjectIdentity) -> Option<usize> {
        if self.main.identity == identity {
            return Some(0);
        }
        self.dependencies
            .iter()
            .position(|slot| slot.identity == identity)
            .map(|index| index + 1)
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
                state: self.slot(index).ok_or(GraphStateError::InvalidObject)?.state,
            });
        }
        let index = self.object_count();
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        if index == SOURCE_ROOT_MAX_OBJECTS {
            return Err(GraphStateError::ObjectCapacity);
        }
        self.dependencies
            .push(ObjectSlot {
                identity,
                state: ObjectState::Discovering,
                mapped_by_transaction: true,
                edge_start: 0,
                edge_count: 0,
            })
            .ok_or(GraphStateError::ObjectCapacity)?;
        Ok(ObjectAdmission::New { index })
    }

    /// Adds one ordered `DT_NEEDED` edge after the child has either been
    /// admitted or found by identity.
    ///
    /// A parent's window grows in place while it is the newest window. If a
    /// depth-first child appended its own edges in between, the parent's
    /// window moves to the end first; its order is unchanged.
    pub(crate) fn attach_needed(
        &mut self,
        parent: usize,
        child: usize,
    ) -> Result<(), GraphStateError> {
        if child >= self.object_count() {
            return Err(GraphStateError::InvalidObject);
        }
        let slot = *self.slot(parent).ok_or(GraphStateError::InvalidObject)?;
        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        if slot.edge_count == SOURCE_ROOT_MAX_NEEDED {
            return Err(GraphStateError::EdgeCapacity);
        }
        let mut start = slot.edge_start;
        if start + slot.edge_count != self.edges.len() {
            start = self.edges.len();
            self.edges
                .reserve(slot.edge_count + 1)
                .ok_or(GraphStateError::EdgeCapacity)?;
            for offset in 0..slot.edge_count {
                let edge = self.edges[slot.edge_start + offset];
                self.edges.push(edge).ok_or(GraphStateError::EdgeCapacity)?;
            }
        }
        self.edges.push(child).ok_or(GraphStateError::EdgeCapacity)?;
        let slot = self.slot_mut(parent)?;
        slot.edge_start = start;
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
    /// a cycle so mapping/rollback stays identity-correct. The owned runtime
    /// follows musl queue_ctors: mark before descending and skip back edges,
    /// emitting each DSO once in depth-first completion order. Legacy private
    /// proof roots retain their original cycle-rejection boundary.
    ///
    /// Like musl queue_ctors, the traversal keeps its own explicit stack, so
    /// a long dependency chain cannot exhaust a small initial process stack.
    pub(crate) fn dependency_first_plan(
        &self,
    ) -> Result<DependencyFirstPlan, GraphStateError> {
        let count = self.object_count();
        if (0..count).any(|index| self.state(index) != Some(ObjectState::Ready)) {
            return Err(GraphStateError::GraphIncomplete);
        }
        let mut marks = LoaderVec::new();
        marks.reserve(count).ok_or(GraphStateError::ObjectCapacity)?;
        for _ in 0..count {
            marks.push(MARK_UNVISITED).ok_or(GraphStateError::ObjectCapacity)?;
        }
        let mut plan = DependencyFirstPlan { indices: LoaderVec::new() };
        // Each frame is an object and the position of its next edge.
        let mut stack: LoaderVec<(usize, usize)> = LoaderVec::new();
        self.enter_dependency(0, &mut marks, &mut stack)?;
        while let Some(&(index, next)) = stack.last() {
            let edges = self.edges(index).ok_or(GraphStateError::InvalidObject)?;
            if let Some(&child) = edges.get(next) {
                if let Some(frame) = stack.last_mut() {
                    frame.1 += 1;
                }
                self.enter_dependency(child, &mut marks, &mut stack)?;
                continue;
            }
            stack.truncate(stack.len() - 1);
            marks[index] = MARK_DONE;
            if index != 0 {
                plan.indices.push(index).ok_or(GraphStateError::ObjectCapacity)?;
            }
        }
        Ok(plan)
    }

    fn enter_dependency(
        &self,
        index: usize,
        marks: &mut [u8],
        stack: &mut LoaderVec<(usize, usize)>,
    ) -> Result<(), GraphStateError> {
        let mark = *marks.get(index).ok_or(GraphStateError::InvalidObject)?;
        match mark {
            #[cfg(feature = "x86_64-owned-dynamic-runtime")]
            MARK_ACTIVE => return Ok(()),
            #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
            MARK_ACTIVE => return Err(GraphStateError::DependencyCycle),
            MARK_DONE => return Ok(()),
            MARK_UNVISITED => {}
            _ => return Err(GraphStateError::InvalidObject),
        }
        if self.state(index) != Some(ObjectState::Ready) {
            return Err(GraphStateError::GraphIncomplete);
        }
        marks[index] = MARK_ACTIVE;
        stack.push((index, 0)).ok_or(GraphStateError::ObjectCapacity)
    }

    /// Drops every transaction-created object in reverse map order and keeps
    /// the kernel main image as the sole discovering slot.  The callback owns
    /// the physical `munmap`; it sees only successfully admitted mappings.
    pub(crate) fn rollback_to_main(&mut self, mut unmap: impl FnMut(usize)) {
        for index in (1..self.object_count()).rev() {
            if self.dependencies[index - 1].mapped_by_transaction {
                unmap(index);
            }
        }
        self.dependencies.truncate(0);
        self.edges.truncate(0);
        self.main.edge_start = 0;
        self.main.edge_count = 0;
        self.main.state = ObjectState::Discovering;
    }

    fn slot(&self, index: usize) -> Option<&ObjectSlot> {
        if index == 0 { Some(&self.main) } else { self.dependencies.get(index - 1) }
    }

    fn slot_mut(&mut self, index: usize) -> Result<&mut ObjectSlot, GraphStateError> {
        if index == 0 {
            return Ok(&mut self.main);
        }
        self.dependencies
            .get_mut(index - 1)
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
    fn dependency_first_plan_ready_cycle_obeys_selected_runtime_contract() {
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

        #[cfg(not(feature = "x86_64-owned-dynamic-runtime"))]
        assert_eq!(graph.dependency_first_plan(), Err(GraphStateError::DependencyCycle));
        #[cfg(feature = "x86_64-owned-dynamic-runtime")]
        assert_eq!(graph.dependency_first_plan().unwrap().indices(), &[right, left]);
    }

    #[cfg(feature = "x86_64-owned-dynamic-runtime")]
    #[test]
    fn installed_graph_has_no_object_or_edge_table_bound() {
        extern crate std;
        // A 40-object fan-out whose last leaf starts a 4000-object chain:
        // more objects than any fixed table, more edges than one slot held,
        // and a postorder deeper than a recursive walk could afford.
        let identity = |inode| ObjectIdentity { device: 2, inode };
        let mut graph = InitialGraphState::new(MAIN);
        let mut leaves = std::vec::Vec::new();
        for inode in 0..40 {
            let ObjectAdmission::New { index } = graph.admit_mapped(identity(inode)).unwrap() else { panic!() };
            graph.attach_needed(0, index).unwrap();
            leaves.push(index);
        }
        let mut parent = *leaves.last().unwrap();
        let mut chain = std::vec::Vec::new();
        for inode in 40..4040 {
            let ObjectAdmission::New { index } = graph.admit_mapped(identity(inode)).unwrap() else { panic!() };
            graph.attach_needed(parent, index).unwrap();
            chain.push(index);
            parent = index;
        }
        for index in 0..graph.object_count() {
            graph.finish_discovery(index).unwrap();
        }
        assert_eq!(graph.object_count(), 4041);
        assert_eq!(graph.edges(0).unwrap(), &leaves[..]);
        let plan = graph.dependency_first_plan().unwrap();
        let mut expected = leaves[..39].to_vec();
        expected.extend(chain.iter().rev());
        expected.push(leaves[39]);
        assert_eq!(plan.indices(), &expected[..]);
    }
}
