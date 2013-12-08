# ===========================================================================
#       http://www.gnu.org/software/autoconf-archive/ax_save_flags.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_SAVE_FLAGS()
#
# DESCRIPTION
#
#   Save common compilation flags into temporary variables
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

AC_DEFUN([AX_SAVE_FLAGS], [
  CPPFLAGS_save="${CPPFLAGS}"
  CFLAGS_save="${CFLAGS}"
  CXXFLAGS_save="${CXXFLAGS}"
  OBJCFLAGS_save="${OBJCFLAGS}"
  LDFLAGS_save="${LDFLAGS}"
  LIBS_save="${LIBS}"
])
