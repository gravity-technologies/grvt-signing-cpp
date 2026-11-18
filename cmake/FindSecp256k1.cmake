# Finds libsecp256k1 with its recovery module (secp256k1_recovery.h) and defines Secp256k1::secp256k1.
# pkg-config, when available, only supplies hints. Set Secp256k1_ROOT, or Secp256k1_INCLUDE_DIR and
# Secp256k1_LIBRARY, for a custom location.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_Secp256k1 QUIET libsecp256k1)
endif()

find_path(Secp256k1_INCLUDE_DIR NAMES secp256k1_recovery.h
  HINTS ${PC_Secp256k1_INCLUDEDIR} ${PC_Secp256k1_INCLUDE_DIRS} /opt/homebrew/include /usr/local/include)
find_library(Secp256k1_LIBRARY NAMES secp256k1
  HINTS ${PC_Secp256k1_LIBDIR} ${PC_Secp256k1_LIBRARY_DIRS} /opt/homebrew/lib /usr/local/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Secp256k1
  REQUIRED_VARS Secp256k1_LIBRARY Secp256k1_INCLUDE_DIR
  REASON_FAILURE_MESSAGE "install libsecp256k1 with the recovery module (Ubuntu: libsecp256k1-dev, macOS: brew install secp256k1)")

if(Secp256k1_FOUND AND NOT TARGET Secp256k1::secp256k1)
  add_library(Secp256k1::secp256k1 UNKNOWN IMPORTED)
  set_target_properties(Secp256k1::secp256k1 PROPERTIES
    IMPORTED_LOCATION "${Secp256k1_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Secp256k1_INCLUDE_DIR}")
endif()
mark_as_advanced(Secp256k1_INCLUDE_DIR Secp256k1_LIBRARY)
