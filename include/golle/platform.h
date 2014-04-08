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

#ifdef _MSC_VER
#define GOLLE_EXTERN __declspec(dllexport)
#elif __GNUC__ >= 4
#define GOLLE_EXTERN extern __attribute__((visibility("default")))
#else
/*!
 * Platform-specific definition for shared library exports.
 */
#define GOLLE_EXTERN extern
#endif

#ifdef _MSC_VER
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
