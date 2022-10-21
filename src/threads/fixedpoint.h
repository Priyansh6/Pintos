#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <stdint.h>

#define FP_SIZE 31
#define P 17
#define Q FP_SIZE - P
#define fp_f (1 << (Q))

typedef int32_t fp32_t;

/* Convert integer to fixed point form. */
#define INT_TO_FP(n) (fp32_t) ((n) * fp_f)

/* Convert x to an integer (round towards 0). */
#define FP_TO_INT_ROUND_TO_ZERO(x) (int32_t) (((fp32_t) (x)) / fp_f)

/* Convert x to an integer (round towards nearest int). */
#define FP_TO_INT(x) (int32_t) (((fp32_t) (x)) >= 0 ? ((((fp32_t) (x))) + fp_f / 2) / fp_f : ((((fp32_t) (x))) - fp_f / 2) / fp_f)

/* Adds two fixed point form integers. */
#define ADD_FP(x, y) (fp32_t) ((fp32_t) (x) + (fp32_t) (y))

/* Subtracts a fixed point form integer from a fixed point form integer. */
#define SUB_FP(x, y) (fp32_t) ((fp32_t) (x) - (fp32_t) (y))

/* Adds an integer to a fixed point integer */
#define ADD_FP_INT(x, n) ADD_FP ((fp32_t) (x), INT_TO_FP (n))

/* Subtract an integer from a fixed point integer */
#define SUB_FP_INT(x, n) SUB_FP ((fp32_t) (x), INT_TO_FP (n))

/* Multiplies two fixed point form integers. */
#define MUL_FP(x, y) (fp32_t) (((int64_t) ((fp32_t) (x))) * ((fp32_t) (y)) / fp_f)

/* Multiplies a fixed point form integer by an integer. */
#define MUL_FP_INT(x, n) (fp32_t) (((fp32_t) (x)) * n)

/* Divides a fixed point form integer by another fixed point form integer. */
#define DIV_FP(x, y) (fp32_t) (((int64_t) ((fp32_t) (x))) * fp_f / ((fp32_t) (y)))

/* Divides a fixed point form integer by an integer. */
#define DIV_FP_INT(x, n) (fp32_t) (((fp32_t) (x)) / n)

/* Load average coefficient (59/60). */
#define LA_COEF (fp32_t) 16110

/* Ready threads coefficient (1/60). */
#define RT_COEF (fp32_t) 273

/* Multiplies a fixed point form integer by 100 and returns an integer. */
#define GET_100X_FP(x) FP_TO_INT(MUL_FP_INT(x, 100))

#endif