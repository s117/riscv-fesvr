// See LICENSE for license details.

#ifndef _FESVR_FESVR_BUILD_INFO_H
#define _FESVR_FESVR_BUILD_INFO_H

#include <cstddef>
#include <cstdio>

// How and from what this libfesvr was built (host, compiler, date, git version...), for data provenance. Defined in a
// source generated at build time by scripts/stamp-build-info.sh.

// The fields, each {key, label, value}: build_hostname, build_host, build_target, cxx_compiler, build_date, build_type,
// repository, version, commit
extern const char *const fesvr_build_info_fields[][3];
extern const size_t fesvr_build_info_num_fields;

// Print them
void fesvr_print_build_info(FILE *fp);

#endif // _FESVR_FESVR_BUILD_INFO_H
