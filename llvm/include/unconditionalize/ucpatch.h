#ifndef _UCPATH_H_
#define _UCPATH_H_

#include <stdint.h>

/* file structure:
* - uint32_t bbcount
* - struct ucpatch_location location[bbcount];
* - struct ucpatch_byte bytes[SUM(location[].count)];
*/

struct ucpatch_location {
    uint32_t offset;
    uint32_t count;
};

struct ucpatch_byte {
    uint64_t offset;
    uint8_t value_orig;
    uint8_t value_golden;
    uint8_t value_faulty;
    uint8_t padding[5];
};

#endif /* defined(_UCPATH_H_) */
