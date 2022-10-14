#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <stdint.h>

//we work in 17.14 format, as detailed in the spec
#define FP_SIZE 31
#define P 17
#define Q FP_SIZE - P
#define f (1 << Q)

typedef union fp {
    int32_t num;
    struct {
        unsigned q    : Q;
        signed p    : P;
        unsigned sign : 1;
    } parts;
}fp;

//convert integer to fixed point
#define INT_TO_FP(n) ((n) * f)

//convert x to an integer (rounding towards 0)
#define FP_TO_INT_ROUND_TO_ZERO(x) ((x) / f)

//convert x to an integer (rounding to nearest int)
#define FP_TO_INT(x) ((x.num) >= 0 ? (((x.num) + f / 2) / f) : (((x.num) - f / 2) / f))

//convert x to a float
//FOR TESTING PURPOSES ONLY
//DO NOT USE INSIDE KERNEL FUNCTION
#define FP_TO_FLOAT(x) ((x.parts.p) + (float) (x.parts.q) / f)

//adds two fixed point numbers --- x + y
#define ADD_FP(x, y) ((x.num) + (y.num))

//subtracts two fixed point numbers --- x - y
#define SUB_FP(x, y) ((x.num) - (y.num))

//adds x (fp) with n (int) --- x + n * f
#define ADD_FP_INT(x, n) ((x.num) + INT_TO_FP(n))

//subtracts n (int) from x (fp) --- x - n * f
#define SUB_FP_INT(x, n) ((x.num) - INT_TO_FP(n))

//multiply two floating point numbers --- x * y
#define MUL_FP(x, y) (int) (((int64_t) x.num) * y.num / f)

//mulitply x (fp) by n (int) --- x * n
#define MUL_FP_INT(x, n) ((x.num) * n)

//divide x (fp) by y (fp) --- x / y
#define DIV_FP(x, y) (int) (((int64_t) x.num) * f / y.num)

//divide x (fp) by n (int) --- x / n
#define DIV_FP_INT(x, n) (x.num / n)

#endif