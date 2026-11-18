
    .text
    .p2align 4
    .globl __crabc_x86_gettext_cabi_dgettext
    .hidden __crabc_x86_gettext_cabi_dgettext
    .type __crabc_x86_gettext_cabi_dgettext,%function
__crabc_x86_gettext_cabi_dgettext:
    b dgettext
    .size __crabc_x86_gettext_cabi_dgettext, .-__crabc_x86_gettext_cabi_dgettext
    .p2align 4
    .globl __crabc_x86_gettext_cabi_dngettext
    .hidden __crabc_x86_gettext_cabi_dngettext
    .type __crabc_x86_gettext_cabi_dngettext,%function
__crabc_x86_gettext_cabi_dngettext:
    b dngettext
    .size __crabc_x86_gettext_cabi_dngettext, .-__crabc_x86_gettext_cabi_dngettext

.section .note.GNU-stack,"",%progbits
