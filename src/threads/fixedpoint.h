#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <stdint.h>

/*      HOW TO USE EXAMPLE
        int example = 23;
        fp x = INT_TO_FP(example);



*/


//we work in 17.14 format, as detailed in the spec
#define FP_SIZE 31
#define P 17
#define Q FP_SIZE - P
#define fp_f (1 << (Q))

typedef union fp {
    int32_t num;
    struct {
        unsigned q    : Q;
        signed p      : P;
        unsigned sign : 1;
    } parts;
}fp;

//convert integer to fixed point
#define INT_TO_FP(n) (fp) ((n) * fp_f)

//convert x to an integer (rounding towards 0)
#define FP_TO_INT_ROUND_TO_ZERO(x) (int) ((((fp) x).num) / fp_f)

//convert x to an integer (rounding to nearest int)
#define FP_TO_INT(x) (int) ((((fp) (x)).num) >= 0 ? (((((fp) x).num) + fp_f / 2) / fp_f) : (((((fp) x).num) - fp_f / 2) / fp_f))

//convert x to a float
//FOR TESTING PURPOSES ONLY
//DO NOT USE INSIDE KERNEL FUNCTION
#define FP_TO_FLOAT(x) (float) ((((fp) x).parts.p) + (float) (((fp) x).parts.q) / fp_f)

//adds two fixed point numbers --- x + y
#define ADD_FP(x, y) (fp) ((((fp) x).num) + (((fp) y).num))

//subtracts two fixed point numbers --- x - y
#define SUB_FP(x, y) (fp) ((((fp) x).num) - (((fp) y).num))

//adds x (fp) with n (int) --- x + n * f
#define ADD_FP_INT(x, n) (ADD_FP((((fp) x).num), INT_TO_FP(n)))

//subtracts n (int) from x (fp) --- x - n * f
#define SUB_FP_INT(x, n) (SUB_FP((((fp) x).num), INT_TO_FP(n)))

//multiply two floating point numbers --- x * y
#define MUL_FP(x, y) (fp) (int32_t) (((int64_t) ((fp) x).num) * ((fp) y).num / fp_f)

//mulitply x (fp) by n (int) --- x * n
#define MUL_FP_INT(x, n) (fp) ((((fp) x).num) * n)

//divide x (fp) by y (fp) --- x / y
#define DIV_FP(x, y) (fp) (int32_t) (((int64_t) ((fp) x).num) * fp_f / ((fp) y).num)

//divide x (fp) by n (int) --- x / n
#define DIV_FP_INT(x, n) (fp) (((fp) x).num / n)

//load average coef = 59/60
#define LA_COEF (fp) (DIV_FP_INT(INT_TO_FP(59), 60))

//ready threads coef = 1/60
#define RT_COEF (fp) (DIV_FP_INT(INT_TO_FP(1), 60))

//calculate load average
#define CALC_LA(la, rt) ( ADD_FP ( MUL_FP (LA_COEF, (la)), MUL_FP(RT_COEF, (rt)) ))

#define RC_COEF(la) (fp) (DIV_FP( MUL_FP_INT ((la), 2) , ADD_FP_INT(MUL_FP_INT ((la), 2), 1) ))

//calculate recent cpu
#define CALC_RECENT_CPU(rc, la, nice) ADD_FP_INT(MUL_FP(RC_COEF(la), (rc)), (nice))

#define DIV_RC_BY_4(rc) (FP_TO_INT ( DIV_FP_INT (rc, 4 ) ))

#define GET_100X_FP(x) FP_TO_INT(MUL_FP_INT(x, 100))


#endif


