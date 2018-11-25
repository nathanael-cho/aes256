#ifndef __AES_INFRASTRUCTURE__
#define __AES_INFRASTRUCTURE__

////////////
// MACROS //
////////////

#define IGNORE(x) if(x) {}

///////////
// TYPES //
///////////

#define uint8_t unsigned char
#define uint32_t unsigned int

///////////////////
// SMALL HELPERS //
///////////////////

inline static void zero_array(uint8_t* array, uint8_t length) {
    volatile uint8_t* to_clear = array;
    for (int i = 0; i < length; i++) {
        to_clear[i] = '\0';
    }
}

inline static void copy_array(uint8_t* destination, uint8_t* source, uint8_t length) {
    for (uint8_t i = 0; i < length; i++) {
        destination[i] = source[i];
    }
}

#endif
