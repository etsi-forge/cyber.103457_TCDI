#include "TDS_CType.h"

bool CreateStorage_Command(TDS::TDSC_SESSION_ID_t& the_session_id, std::string& storage_name, TDS::TDSC_CONTAINER_ID_t& the_container_id);
bool StoreData_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id, std::string& data_string, TDS::TDSC_OBJECT_ID_t& the_object_id);
bool GetStorageValue_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id, TDS::TDSC_OBJECT_ID_t& the_object_id, TDS::TDSC_DATA_t& object_data);
bool GetStorage_Command(TDS::TDSC_SESSION_ID_t& the_session_id, std::string& storage_name, TDS::TDSC_CONTAINER_ID_t&);
bool DeleteStorage_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id);
