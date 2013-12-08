# ===========================================================================
#     http://www.gnu.org/software/autoconf-archive/ax_restore_flags.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_RESTORE_FLAGS()
#
# DESCRIPTION
#
#   Restore common compilation flags from temporary variables
#
# LICENSE
#
#   Copyright (c) 2009 Filippo Giunchedi <filippo@esaurito.net>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 3

AC_DEFUN([AX_RESTORE_FLAGS], [
  CPPFLAGS="${CPPFLAGS_save}"
  CFLAGS="${CFLAGS_save}"
  CXXFLAGS="${CXXFLAGS_save}"
  OBJCFLAGS="${OBJCFLAGS_save}"
  LDFLAGS="${LDFLAGS_save}"
  LIBS="${LIBS_save}"
])
