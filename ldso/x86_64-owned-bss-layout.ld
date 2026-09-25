/*
 * Installed x86 interpreter link input: layout only.
 *
 * The 64 KiB static pool chunk is page aligned and consumed from its start,
 * so a startup touches only its first pages. Left in link order it split the
 * loader's small .bss statics over two pages on either side of it; placing
 * it last keeps them together and the unused chunk tail after them.
 */
SECTIONS { .bss.crabc.static_chunk (NOLOAD) : { *(.bss.*STATIC_CHUNK*) } }
INSERT AFTER .bss;
