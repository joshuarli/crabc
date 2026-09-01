/*
 * Compile-only GCC-plugin capability probe for x86 header callables.
 *
 * The x86 evidence image exposes GCC's plugin headers but does not install
 * their development-header dependency.  This source intentionally exercises
 * the exact front-end API a declaration backend would need, without claiming
 * to be such a backend.  `header_callable_gcc_fallback_probe.py` compiles it
 * in a temporary directory and records the fail-closed result.
 */

#include "gcc-plugin.h"
#include "plugin-version.h"
#include "tree.h"

int plugin_is_GPL_compatible;

namespace {

void inspect_finished_declaration(void *gcc_data, void *) {
  tree declaration = static_cast<tree>(gcc_data);
  if (declaration == NULL_TREE || TREE_CODE(declaration) != FUNCTION_DECL) {
    return;
  }

  /* Reference every field needed by the canonical archive-vs-inline split. */
  (void) DECL_SOURCE_FILE(declaration);
  (void) DECL_SOURCE_LINE(declaration);
  (void) DECL_EXTERNAL(declaration);
  (void) TREE_STATIC(declaration);
  (void) DECL_DECLARED_INLINE_P(declaration);
  (void) DECL_INITIAL(declaration);
}

}  // namespace

extern "C" int plugin_init(plugin_name_args *plugin_info, plugin_gcc_version *version) {
  if (plugin_info == nullptr || !plugin_default_version_check(version, &gcc_version)) {
    return 1;
  }
  register_callback(plugin_info->base_name, PLUGIN_FINISH_DECL, inspect_finished_declaration, nullptr);
  return 0;
}
