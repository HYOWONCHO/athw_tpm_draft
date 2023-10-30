/********************************************************************************
 * Copyright (C) 2020 by Trustkey                                               * 
 * This file is part of  Project                                                *   
 * This software contains confidential information of TrustKey Co.,Ltd.         *
 * and unauthorized distribution of this software, or any portion of it, are    *
 * prohibited.                                                                  *
 ********************************************************************************/

/**
 * @file athw_mem.c
 * Memory operation
 *
 * @anchor LEON_SYSTEM
 * @author Leon, (c) Trustkey
 * @version Draft 
 * @date 2023-10-27
 * @bug No known bugs.
 * @note 
 * 
 * @copyright Copyright 2020 Trustkey. All rights reserved*
 */

#include "athw_mem.h"
#include "tpm_errno.h"
#include "log.h"
 
 
static void mem_prim_set (void *dest, uint32_t len, uint8_t value)
{
    uint8_t *dp;
    uint32_t count;
    uint32_t lcount;

    uint32_t *lp;
    uint32_t value32;

    count = len;

    dp = dest;

    value32 = value | (value << 8) | (value << 16) | (value << 24);

    /*
     * First, do the few bytes to get uint32_t aligned.
     */
    for (; count && ( (uintptr_t)dp & (sizeof(uint32_t)-1) ); count--) {
        *dp++ = value;
    }

    /*
     * Then do the uint32_ts, unrolled the loop for performance
     */
    lp = (uint32_t *)dp;
    lcount = count >> 2;

    while (lcount != 0) {

        switch (lcount) {
        /*
         * Here we do blocks of 8.  Once the remaining count
         * drops below 8, take the fast track to finish up.
         */
        default:
            *lp++ = value32; *lp++ = value32; *lp++ = value32; *lp++ = value32;
            *lp++ = value32; *lp++ = value32; *lp++ = value32; *lp++ = value32;
            *lp++ = value32; *lp++ = value32; *lp++ = value32; *lp++ = value32;
            *lp++ = value32; *lp++ = value32; *lp++ = value32; *lp++ = value32;
            lcount -= 16;
            break;

        case 15:  *lp++ = value32;
        case 14:  *lp++ = value32;
        case 13:  *lp++ = value32;
        case 12:  *lp++ = value32;
        case 11:  *lp++ = value32;
        case 10:  *lp++ = value32;
        case 9:  *lp++ = value32;
        case 8:  *lp++ = value32;

        case 7:  *lp++ = value32;
        case 6:  *lp++ = value32;
        case 5:  *lp++ = value32;
        case 4:  *lp++ = value32;
        case 3:  *lp++ = value32;
        case 2:  *lp++ = value32;
        case 1:  *lp++ = value32;
            lcount = 0;
            break;
        }
    } /* end while */


    dp = (uint8_t *)lp;

    /*
     * compute the number of remaining bytes
     */
    count &= (sizeof(uint32_t)-1);

    /*
     * remaining bytes
     */
    for (; count; dp++, count--) {
        *dp = value;
    }

    return;
}

static void mem_prim_move (void *dest, const void *src, uint32_t len)
{

#define wsize   sizeof(uint32_t)
#define wmask   (wsize - 1)

    uint8_t *dp = dest;
    const uint8_t *sp = src;

    uint32_t tsp;

    /*
     * Determine if we need to copy forward or backward (overlap)
     */
    if ((uintptr_t)dp < (uintptr_t)sp) {
        /*
         * Copy forward.
         */

        /*
         * get a working copy of src for bit operations
         */
        tsp = (uintptr_t)sp;

        /*
         * Try to align both operands.  This cannot be done
         * unless the low bits match.
         */
        if ((tsp | (uintptr_t)dp) & wmask) {
            /*
             * determine how many bytes to copy to align operands
             */
            if ((tsp ^ (uintptr_t)dp) & wmask || len < wsize) {
                tsp = len;

            } else {
                tsp = wsize - (tsp & wmask);
            }

            len -= tsp;

            /*
             * make the alignment
             */
            do {
                *dp++ = *sp++;
            } while (--tsp);
        }

        /*
         * Now copy, then mop up any trailing bytes.
         */
        tsp = len / wsize;

        if (tsp > 0) {

            do {
                *(uint32_t *)dp = *(uint32_t *)sp;

                sp += wsize;
                dp += wsize;
            } while (--tsp);
        }

        /*
         * copy over the remaining bytes and we're done
         */
        tsp = len & wmask;

        if (tsp > 0) {
            do {
                *dp++ = *sp++;
            } while (--tsp);
        }

    } else {
        /*
         * This section is used to copy backwards, to handle any
         * overlap.  The alignment requires (tps&wmask) bytes to
         * align.
         */

        /*
         * go to end of the memory to copy
         */
        sp += len;
        dp += len;

        /*
         * get a working copy of src for bit operations
         */
        tsp = (uintptr_t)sp;

        /*
         * Try to align both operands.
         */
        if ((tsp | (uintptr_t)dp) & wmask) {

            if ((tsp ^ (uintptr_t)dp) & wmask || len <= wsize) {
                tsp = len;
            } else {
                tsp &= wmask;
            }

            len -= tsp;

            /*
             * make the alignment
             */
            do {
                *--dp = *--sp;
            } while (--tsp);
        }

        /*
         * Now copy in uint32_t units, then mop up any trailing bytes.
         */
        tsp = len / wsize;

        if (tsp > 0) {
            do {
                sp -= wsize;
                dp -= wsize;

                *(uint32_t *)dp = *(uint32_t *)sp;
            } while (--tsp);
        }

        /*
         * copy over the remaining bytes and we're done
         */
        tsp = len & wmask;
        if (tsp > 0) {
            tsp = len & wmask;
            do {
                *--dp = *--sp;
            } while (--tsp);
        }
    }

    return;
}
 
int athw_memset_s(void *dest, int len, uint8_t value)
{
    if(dest == NULL) {
        tr_log("dest is null");
        return -ATHW_ENULLP;
    }
    
    if(len == 0) {
        tr_log("len is 0");
        return -ATHW_ESZEROL;
    }
    
    mem_prim_set(dest,len, value);

    return ATHW_EOK;

    
    
}

int athw_memzero_s(void *dest, size_t len)
{
    if(dest == NULL) {
        tr_log("dest is null");
        return -ATHW_ENULLP;
    }

    if(len == 0) {
        tr_log("len is 0");
        return -ATHW_ESZEROL;
    }
    
    mem_prim_set(dest,len, 0);
    
    return ATHW_EOK;
 
}

int athw_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax)
{
    uint8_t *dp;
    const uint8_t *sp;
    
    dp = dest;
    sp = src;
    
    if (dp == NULL) {
        return -ATHW_ENULLP;
    }
    
    if (dmax == 0 || smax == 0) {
        return -ATHW_ESZEROL;
    }
    
    if (smax > dmax) {
        mem_prim_set(dp, dmax, 0);
        return -ATHW_ESLMAX;
    }
    
    // overlap is undefined behavior, do now allow
    // memory overlap
    if( ((dp > sp) && (dp < (sp+smax))) ||
        ((sp > dp) && (sp < (dp+dmax))) ) {
        mem_prim_set(dp, dmax, 0);
        return -ATHW_ESOVRLP;
    }
    
    mem_prim_move(dp, sp, smax);
    
    return ATHW_EOK;
}

