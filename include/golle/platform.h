/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_PLATFORM_H
#define LIBGOLLE_PLATFORM_H

/*!
 * \file golle/platform.h
 * \author Anthony Arnold
 * \copyright MIT License
 * \date 2014
 * \brief Macros for platform-dependant behaviour.
 */

#undef GOLLE_MSC
#ifdef _MSC_VER
#define GOLLE_MSC _MSC_VER
#endif

#undef GOLLE_GNUC
#ifdef __GNUC__
#define GOLLE_GNUC __GNUC__
#endif

#undef GOLLE_WINDOWS
#if \
  defined(_WIN32) ||				\
  defined(_WIN64) ||\
  defined(__WIN32__) ||\
  defined(__TOS_WIN__) ||\
  defined(__WINDOWS__)

#define GOLLE_WINDOWS 1

#endif

#if GOLLE_MSC
#define GOLLE_EXTERN __declspec(dllexport)
#elif GOLLE_GNUC >= 4
#define GOLLE_EXTERN extern __attribute__((visibility("default")))
#else
/*!
 * Platform-specific definition for shared library exports.
 */
#define GOLLE_EXTERN extern
#endif

#if GOLLE_MSC
#define GOLLE_INLINE static __inline
#else
/*!
 * Platform-specific definition proper inlining.
 */
#define GOLLE_INLINE static inline
#endif

#ifdef __cplusplus
#define GOLLE_BEGIN_C extern "C" {
#define GOLLE_END_C  }
#else
/*!
 * For C++ compilers, begins an `extern "C"` block.
 */
#define GOLLE_BEGIN_C
/*!
 * For C++ compilers, ends and `extern "C"` block.
 */
#define GOLLE_END_C
#endif


#endif
