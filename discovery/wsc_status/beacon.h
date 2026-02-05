#ifndef BEACON_H
#define BEACON_H

#include <windows.h>
#include <stdint.h>

// Beacon output types
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

// Beacon data parser structure
typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} datap;

// Beacon API declarations
DECLSPEC_IMPORT void BeaconPrintf(int type, char * fmt, ...);
DECLSPEC_IMPORT void BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT int  BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int  BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char * BeaconDataExtract(datap * parser, int * size);

// Beacon output functions
DECLSPEC_IMPORT void BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void BeaconFormatAlloc(void ** outdata, int * size);
DECLSPEC_IMPORT void BeaconFormatReset(void * outdata);
DECLSPEC_IMPORT void BeaconFormatFree(void * outdata);
DECLSPEC_IMPORT void BeaconFormatAppend(void * outdata, char * text, int len);
DECLSPEC_IMPORT void BeaconFormatPrintf(void * outdata, char * fmt, ...);
DECLSPEC_IMPORT void BeaconFormatToString(void * outdata, char ** text, int * len);
DECLSPEC_IMPORT void BeaconFormatInt(void * outdata, int value);

#endif // BEACON_H

