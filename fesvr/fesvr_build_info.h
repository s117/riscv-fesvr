// See LICENSE for license details.

#ifndef _FESVR_FESVR_BUILD_INFO_H
#define _FESVR_FESVR_BUILD_INFO_H

#include <cstdio>

// Print how and from what this libfesvr was built (host, compiler, date, git version...), for data provenance.
// Defined in a source generated at build time by scripts/stamp-build-info.sh.
void fesvr_print_build_info(FILE *fp);

#endif // _FESVR_FESVR_BUILD_INFO_H
