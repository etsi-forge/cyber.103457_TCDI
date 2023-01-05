#include "TDS_CType.h"

bool GetRandom_Command(TDS::TDSC_SESSION_ID_t & the_session_id, TDS::TDSC_SIZE_IN_BYTES_t size_in_byte, TDS::TDSC_OBJECT_ID_t&);
bool GetTrustedTimestamping_Command(TDS::TDSC_SESSION_ID_t & the_session_id, TDS::TDSC_OBJECT_ID_t&);
bool GetEncryptionKey_Command(TDS::TDSC_SESSION_ID_t & the_session_id, TDS::TDSC_KEY_TYPE_t key_type, TDS::TDSC_OBJECT_ID_t&);
