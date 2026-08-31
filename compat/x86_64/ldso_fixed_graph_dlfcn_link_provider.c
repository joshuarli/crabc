/*
 * Link-only definition for the strong-import negative executable. The runner
 * links against a DSO with the real fixture SONAME, then launches against the
 * ordinary DSO that does not define this record. The candidate interpreter
 * must therefore reject the main image's strong import instead of treating
 * its private record as ambient global lookup policy.
 */
const unsigned char __crabc_x86_64_fixed_graph_dlfcn_v1[64];
