#include "TDS_CType.h"

bool CreateArchive_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id);
bool Archive_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id, std::string& data_string);
bool CloseArchive_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id);
