#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <list>
#include <memory>
#include <new>
#include <type_traits>
#include <vector>
#include <unistd.h>
#include "mimalloc.h"

static int failures, deletes, destroys, new_calls;
extern "C" void __real_mi_heap_delete(mi_heap_t*);
extern "C" void __real_mi_heap_destroy(mi_heap_t*);
extern "C" void __wrap_mi_heap_delete(mi_heap_t* h) { ++deletes; __real_mi_heap_delete(h); }
extern "C" void __wrap_mi_heap_destroy(mi_heap_t* h) { ++destroys; __real_mi_heap_destroy(h); }
static void check(const char* name, bool value) {
  std::printf("%s=%d\n", name, int(value)); failures += !value;
}
static void returning_handler() { ++new_calls; }
static void throwing_handler() { ++new_calls; throw std::bad_alloc(); }
struct value {
  static int live;
  int data;
  explicit value(int n) : data(n) { ++live; }
  value(const value& x) : data(x.data) { ++live; }
  ~value() { --live; }
};
int value::live;

template<template<class> class Alloc> static void lifetime(bool destroying) {
  using A = Alloc<unsigned long>;
  using B = typename std::allocator_traits<A>::template rebind_alloc<value>;
  static_assert(!std::allocator_traits<A>::is_always_equal::value, "Heap identity is allocator equality");
  static_assert(std::allocator_traits<A>::propagate_on_container_copy_assignment::value, "copy propagates Heap");
  static_assert(std::allocator_traits<A>::propagate_on_container_move_assignment::value, "move propagates Heap");
  static_assert(std::allocator_traits<A>::propagate_on_container_swap::value, "swap propagates Heap");
  const int before_delete = deletes, before_destroy = destroys;
  unsigned long* survivor = nullptr;
  {
    A first;
    A other;
    check("stl.distinct", first != other);
    {
      A copy(first);
      A selected = first.select_on_container_copy_construction();
      B rebound(first);
      check("stl.copy_rebind", first == copy && first == selected && first == rebound);
      check("stl.max_size", copy.max_size() == size_t(PTRDIFF_MAX) / sizeof(unsigned long));
      survivor = copy.allocate(3, nullptr);
      check("stl.allocate", survivor && mi_heap_of(survivor) != mi_heap_main());
      if (!survivor) std::_Exit(1);
      survivor[0] = 0x5a;
      {
        std::vector<value, B> values(rebound);
        values.emplace_back(17);
        values.emplace_back(29);
        std::vector<value, B> copied(values);
        std::list<value, B> nodes(rebound);
        nodes.emplace_back(41);
        check("stl.containers", values[0].data == 17 && copied[1].data == 29 && nodes.front().data == 41 &&
              copied.get_allocator() == rebound && mi_heap_of(values.data()) == mi_heap_of(survivor));
      }
      check("stl.object_destruction", value::live == 0);
      copy.deallocate(survivor, 3);
      /* Destroying deallocate is deliberately a no-op while owners remain. */
      if (destroying) check("stl.destroying_deallocate", survivor[0] == 0x5a && mi_heap_of(survivor) != mi_heap_main());
      else survivor = copy.allocate(3);
      if (!survivor) std::_Exit(1);
      survivor[0] = 0x5a;
      copy.collect(false);
      copy.collect(true);
      check("stl.shared_lifetime", deletes == before_delete && destroys == before_destroy && survivor[0] == 0x5a);
    }
    check("stl.copy_destruction", deletes == before_delete && destroys == before_destroy && survivor[0] == 0x5a);
  }
  check("stl.last_owner", destroying ? destroys == before_destroy + 2 && deletes == before_delete :
                                      deletes == before_delete + 2 && destroys == before_destroy);
  /* Delete preserves live clients in the main Heap; destroy consumes them.
     Do not observe a client or Heap after destruction. */
  if (!destroying) {
    check("stl.deleted_client", survivor[0] == 0x5a && mi_heap_of(survivor) == mi_heap_main());
    mi_free(survivor);
  }
  mi_heap_t* borrowed_heap = mi_heap_new();
  const int borrowed_deletes = deletes, borrowed_destroys = destroys;
  {
    A borrowed(borrowed_heap);
    A copied(borrowed);
    B rebound(borrowed);
    auto p = copied.allocate(3);
    check("stl.borrowed", p && mi_heap_of(p) == borrowed_heap && copied == rebound);
    copied.deallocate(p, 3);
  }
  check("stl.borrowed_lifetime", deletes == borrowed_deletes && destroys == borrowed_destroys);
  auto p = mi_heap_zalloc_tp(unsigned long, borrowed_heap);
  check("stl.borrowed_still_live", p && *p == 0 && mi_heap_of(p) == borrowed_heap);
  mi_free(p);
  mi_heap_destroy(borrowed_heap);
}

int main(int argc, char** argv) {
  if (argc == 2) {
    mi_heap_destroy_stl_allocator<unsigned long> a;
    volatile size_t overflow = std::numeric_limits<size_t>::max() / sizeof(unsigned long) + 1;
    if (std::strcmp(argv[1], "overflow-throw") == 0 || std::strcmp(argv[1], "refusal-throw") == 0) {
      std::set_new_handler(throwing_handler);
      volatile size_t count = std::strcmp(argv[1], "overflow-throw") == 0 ? overflow :
          std::numeric_limits<size_t>::max() / sizeof(unsigned long);
      bool caught = false;
      try { auto p = a.allocate(count); (void)p; }
      catch (const std::bad_alloc&) { caught = true; }
      check("stl.throwing_handler", caught && new_calls == 1);
      std::set_new_handler(nullptr);
      auto p = a.allocate(3);
      check("stl.after_exception", p && mi_heap_of(p) != mi_heap_main());
      a.deallocate(p, 3);
      std::fflush(stdout);
      _exit(failures ? 1 : 0);
    }
    if (std::strcmp(argv[1], "overflow-handler") == 0) {
      std::set_new_handler(returning_handler);
      auto p = a.allocate(overflow);
      check("stl.overflow_handler", p == nullptr && new_calls == 1);
      std::set_new_handler(nullptr);
      std::fflush(stdout);
      _exit(failures ? 1 : 0);
    }
    if (std::strcmp(argv[1], "refusal-handler") == 0) {
      std::set_new_handler(returning_handler);
      volatile size_t huge = std::numeric_limits<size_t>::max() / sizeof(unsigned long);
      auto p = a.allocate(huge);
      check("stl.refusal_handler", p == nullptr && new_calls == 1);
      std::set_new_handler(nullptr);
      std::fflush(stdout);
      _exit(failures ? 1 : 0);
    }
    if (std::strcmp(argv[1], "overflow-abort") == 0) {
      std::set_new_handler(nullptr);
      auto p = a.allocate(overflow);
      (void)p;
      _exit(2);
    }
    return 2;
  }
  lifetime<mi_heap_stl_allocator>(false);
  lifetime<mi_heap_destroy_stl_allocator>(true);
  std::fflush(stdout);
  _exit(failures ? 1 : 0);
}
