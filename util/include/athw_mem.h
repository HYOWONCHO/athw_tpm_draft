#ifndef _ATHW_MEM_H
#define _ATHW_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>


/**
 * Sets at the dest to specified value
 * 
 * @author rocke (2023-10-27)
 * 
 * @param dest   destnation buffer address
 * @param len    length of buffer
 * @param value  buffer set value
 * 
 * @return on success, return 0, negative on failgure 
 */
int athw_memset_s(void *dest, int len, uint8_t value);


/**
 * Sets  dest to 0 
 *  
 * @author rocke (2023-10-27)
 * 
 * @param dest   destnation buffer address
 * @param len    length of buffer
 * 
 * @return on success, return 0, negative on failgure 
 */

int athw_memzero_s(void *dest, size_t len);

/**
 * copies at most smax bytes from src to dest
 * 
 * @author rocke (2023-10-27)
 * 
 * @param dest   
 * @param dmax   
 * @param src    
 * @param smax   
 * 
 * @return int 
 */
int athw_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax);


#ifdef __cplusplus
}
#endif 
#endif





                       
