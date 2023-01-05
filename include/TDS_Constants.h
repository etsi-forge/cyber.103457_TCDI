#ifndef TDS_CONSTANTS_H
#define TDS_CONSTANTS_H

#define TD_OPENCONNECTION_CMD           0x01
#define TD_OPENCONNECTION_RSP           0x02
#define TD_CLOSECONNECTION_CMD			0x03
#define TD_CLOSECONNECTION_RSP			0x04

#define TD_CREATESESSION_CMD            0x10
#define TD_CREATESESSION_RSP            0x11
#define TD_CLOSESESSION_CMD             0x12
#define TD_CLOSESESSION_RSP             0x13

#define TD_CREATEOBJECT_CMD             0x20
#define TD_CREATEOBJECT_RSP             0x21
#define TD_PUTOBJECTVALUE_CMD           0x22
#define TD_PUTOBJECTVALUE_RSP           0x23
#define TD_GETOBJECTVALUE_CMD           0x24
#define TD_GETOBJECTVALUE_RSP           0x25

#define TD_CREATEARCHIVE_CMD            0x30
#define TD_CREATEARCHIVE_RSP            0x31
#define TD_ARCHIVE_CMD                  0x32
#define TD_ARCHIVE_RSP                  0x33
#define TD_CLOSEARCHIVE_CMD             0x34
#define TD_CLOSEARCHIVE_RSP             0x35

#define TD_CREATESTORAGE_CMD            0x40
#define TD_CREATESTORAGE_RSP            0x41
#define TD_DELETESTORAGE_CMD            0x42
#define TD_DELETESTORAGE_RSP            0x43
#define TD_STOREDATA_CMD                0x44
#define TD_STOREDATA_RSP                0x45
#define TD_GETSTORAGEVALUE_CMD          0x46
#define TD_GETSTORAGEVALUE_RSP          0x47
#define TD_GETSTORAGE_CMD               0x48
#define TD_GETSTORAGE_RSP               0x49
#define TD_SEARCH_CMD                   0x4A
#define TD_SEARCH_RSP                   0x4B

#define TD_GETRANDOM_CMD                0x50
#define TD_GETRANDOM_RSP                0x51
#define TD_GENERATEENCRYPTIONKEY_CMD    0x52
#define TD_GENERATEENCRYPTIONKEY_RSP    0x53
#define TD_GETTRUSTEDTIMESTAMP_CMD      0x54
#define TD_GETTRUSTEDTIMESTAMP_RSP      0x55
#define TD_TRUSTRENEWAL_CMD             0x56
#define TD_TRUSTRENEWAL_RSP             0x57

#define TD_GETVALUE_CMD                 0x60
#define TD_GETVALUE_RSP                 0x61

#define TD_DUMPCONNECTION_CMD			0xA0
#define TD_DUMPCONNECTION_RSP			0xA1

#define APP_KILLSWITCH_CMD				0xB0
#define APP_KILLSWITCH_RSP				0xB1

#define TD_TTLV_TYPE_SYMBOL             0x1
#define TD_TTLV_TYPE_BYTESTRING         0x2
#define TD_TTLV_TYPE_UNICODESTRING      0x3
#define TD_TTLV_TYPE_INTEGER            0x4
#define TD_TTLV_TYPE_SHORTINTEGER       0x5
#define TD_TTLV_TYPE_PAIR               0x6
#define TD_TTLV_TYPE_UUID               0x7

#define TD_TTLV_TAG_LTDID               0x01
#define TD_TTLV_TAG_LTDROLE             0x02
#define TD_TTLV_TAG_CN                  0x03

#define TD_TTLV_TAG_OBJECTID            0x10
#define TD_TTLV_TAG_SESSIONID           0x11
#define TD_TTLV_TAG_CONTAINERID         0x12

#define TD_TTLV_TAG_CONTAINERNAME       0x20
#define TD_TTLV_TAG_CONTAINERTYPE       0x21

#define TD_TTLV_TAG_SIGNEDDATA          0x30

#define TD_TTLV_TAG_DBKEYVALUE          0x40
#define TD_TTLV_TAG_DBKEY               0x41
#define TD_TTLV_TAG_DBVALUE             0x42

#define TD_TTLV_TAG_STATUSCODE          0x50

#define TD_TTLV_TAG_PERMANENTFILE       0x60
#define TD_TTLV_TAG_PERMANENTDATABASE   0x61
#define TD_TTLV_TAG_FILE                0x62
#define TD_TTLV_TAG_DATABASE            0x63

#define TD_TTLV_TAG_EVENT               0x70

#define TD_TTLV_TAG_SUBJECT             0x80
#define TD_TTLV_TAG_CONTEXT             0x81

#define TD_TTLV_TAG_SIZEINBYTES         0x90
#define TD_TTLV_TAG_DATA                0x91
#define TD_TTLV_TAG_NONCE               0x92

#define TD_TTLV_TAG_KEYTYPE             0xA0
#define TD_TTLV_TAG_RSAKEY1024          0xA1
#define TD_TTLV_TAG_RSAKEY2048          0xA2
#define TD_TTLV_TAG_RSAKEY4096          0xA3
#define TD_TTLV_TAG_SYMMETRICKEY128     0xA4
#define TD_TTLV_TAG_SYMMETRICKEY256     0xA5

#define TDSC_CONTAINER_TYPE_FILE 			0x01
#define TDSC_CONTAINER_TYPE_DATABASE 		0x02
#define TDSC_CONTAINER_TYPE_PERM_FILE		0x03
#define TDSC_CONTAINER_TYPE_PERM_DATABASE	0x04

#endif
