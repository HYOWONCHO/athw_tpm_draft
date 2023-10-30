/*
 * log.h
 *
 *  Created on: 2023. 9. 12.
 *      Author: rocke
 */

#ifndef INCLUDE_LOG_H_
#define INCLUDE_LOG_H_

#include <stdio.h>

#ifdef DEBUG
#   define _DEBUG           1
#else
#   define _DEBUG       0
#endif


#define _PANIC_HANG                                     \
({                                                      \
    while(1)                                            \
    ;                                                   \
}) 

#ifndef pr_fmt
#define pr_fmt(fmt)     fmt
#endif

// ##__VA_ARGS__ == ##args
#define log(_cat, _level, _fmt, _args...)               \
({                                                      \
    int _l = (int)_level;                               \
    if(_LOG_DEBUG != 0 || _l <= LOG_INFO ||             \
       (_DEBUG && _L == LOGL_DEBUG))                    \
       printf("[LOG (%d) %s:%d]"_fmt,"\r\r\n",            \
           _l, __FUNCTION__, __LINE__, ##_VA_ARGS__);   \
})

#define debug_cond(cond, fmt, args...)                  \
({                                                      \
    if(cond) {                                          \
        printf(pr_fmt(fmt), ##args);                    \
    }                                                   \
})


#define debug(fmt, args...)                             \
    debug_cond(_DEBUG, fmt, ##args)


#define tr_log(fmt,...) printf("[%s:%u] "fmt "\r\r\n",__FUNCTION__,__LINE__,##__VA_ARGS__)
#define tr_print        printf
//#define tr_log(...) printf("%s:%d \r\r\n",__FUNCTION__,__LINE__,##__VA_ARGS__);printf("\r\r\n")

#define _buf_dump(P,T,L) \
    ({  \
        tr_print("\r\r\n[HEX]");  \
        if((void *)T != NULL) tr_print("%-16.16s(%04d): ", (char *)T, (int)L);  \
        \
        tr_print("\r\r\n%-10s", "Offset(h)"); \
        for(int i = 0; i < 0x10; i++) tr_print("%02x ",i);  \
        \
        for(int i = 0; i < (int)L; i++) {   \
            if (i%0x10 == 0) tr_print("\r\r\n%08X  ", i); \
            tr_print("%02x ", ((char *)P)[i] & 0xFF);   \
        }\
        \
        tr_print("\r\r\n");   \
     })


#define LINE_LEN 16
static inline void _athw_print_bin(const uint8_t *title, const uint8_t* buffer, uint32_t length)
{
    uint32_t i, sz;
    
    if(title) {
        printf("----  %s (length of buffer: %d) \r\r\n", title, length) ;
    }

    if (!buffer) {
        printf("\tNULL\r\n");
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        printf("\t");
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                printf("%02x ", buffer[i]);
            else
                printf("   ");
        }
        printf("| ");
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                printf("%c", buffer[i]);
            else
                printf(".");
        }
        printf("\r\r\n");


        buffer += sz;
        length -= sz;
    }
}
#endif /* INCLUDE_LOG_H_ */
