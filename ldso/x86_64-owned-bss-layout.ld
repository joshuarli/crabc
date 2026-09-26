/*
 * Installed x86 interpreter link input: layout only.
 *
 * The initialized .data occupies only part of its last page. Keep the small
 * mutable statics in that page, then place the page-aligned initial TLS image
 * and the 64 KiB static pool chunk after it. Startup reads the initial TLS
 * image and consumes the pool from its start; the unused pool tail stays cold.
 */
SECTIONS {
  .bss.crabc.initial_tls (NOLOAD) : { *(.bss.*BUILTIN_INITIAL_TLS*) }
  .bss.crabc.static_chunk (NOLOAD) : { *(.bss.*STATIC_CHUNK*) }
}
INSERT AFTER .bss;
SECTIONS { .bss.crabc.small (NOLOAD) : { *(.bss.*) } }
INSERT AFTER .data;
