# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side hashing and cracking -
# computing a digest with one of many algorithms, identifying a hash,
# recovering a preimage with hashcat or John the Ripper, looking one up in
# a rainbow table, and reading a set of hashes as a credential-strength
# posture. Built as a shared library on the engine platform only, like
# tapi_smb: it calls tapi and tapi_job, engine libraries with no static
# variant, so a static build of it would fail the configure.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_hash.h',
    'tapi_hash_audit.h',
    'tapi_hash_crack.h',
    'tapi_hash_rainbow.h',
)

# tapi_hash_internal.h is internal to this library and is not installed.
sources += files(
    'tapi_hash.c',
    'tapi_hash_audit.c',
    'tapi_hash_cmd.c',
    'tapi_hash_crack.c',
    'tapi_hash_rainbow.c',
)

te_libs += [
    'tapi',
    'tapi_job',
    'tapi_devtool',
    'tapi_cybersec',
]
