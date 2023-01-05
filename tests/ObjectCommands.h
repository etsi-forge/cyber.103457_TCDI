#include "TDS_CType.h"

bool CreateObject_Command(TDS::TDSC_SESSION_ID_t&, TDS::TDSC_OBJECT_ID_t&);
bool PutObjectValue_Command(TDS::TDSC_SESSION_ID_t&, TDS::TDSC_OBJECT_ID_t, TDS::TDSC_DATA_t&);
bool GetObjectValue_Command(TDS::TDSC_SESSION_ID_t&, TDS::TDSC_OBJECT_ID_t, TDS::TDSC_DATA_t&);
