#! /bin/sh
MEMC_VERSION=`git describe | tr '-' '_'`;
cat > .libs/config_version.h << EOF
#ifndef CONFIG_VERSION_H
#define CONFIG_VERSION_H

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "memcached $MEMC_VERSION"

/* Define to the version of this package. */
#define PACKAGE_VERSION "$MEMC_VERSION"

/* Version number of package */
#define VERSION "$MEMC_VERSION"

#endif // CONFIG_VERSION_H
EOF
