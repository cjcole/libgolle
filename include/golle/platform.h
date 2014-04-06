/*
 * Copyright (C) Anthony Arnold 2014
 */

#ifndef LIBGOLLE_PLATFORM_H
#define LIBGOLLE_PLATFORM_H

/*!
 * \file golle/platform.h
 * \brief Macros for platform-dependant behaviour.
 */

/*!
 * \cond NODOXYGEN
 */

#ifdef _MSC_VER
#define GOLLE_EXTERN __declspec(dllexport)
#elif __GNUC__ >= 4
#define GOLLE_EXTERN extern __attribute__((visibility("default")))
#else
#define GOLLE_EXTERN extern
#endif

#ifdef _MSC_VER
#define GOLLE_INLINE static __inline
#else
#define GOLLE_INLINE static inline
#endif

#ifdef __cplusplus
#define GOLLE_BEGIN_C extern "C" {
#define GOLLE_END_C  }
#else
#define GOLLE_BEGIN_C
#define GOLLE_END_C
#endif

/*!
 * \endcond NODOXYGEN
 */


#endif
