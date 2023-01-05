#include <fstream>

#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_Object.h"
#include "TDS_Container.h"
#include "TDS_Storage_Commands.h"

#include <botan/secmem.h>
#include <botan/base64.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>

namespace TDS {

    auto sto_logger = spdlog::stdout_color_mt("sto_cmd");       /*!< Storage Commands related spdlog Logger */
    const std::string default_storage_path = "/tmp/";           /*!< Default root path to store Storage files */  
    const std::string default_storage_prefix = "STO";          /*!< Default storage prefix */

    /* TD_CreateStorage_Command */

    TD_CreateStorage_Command::TD_CreateStorage_Command() : TD_Command() {
        _response_id = TD_CREATESTORAGE_RSP;
    }

    TD_CreateStorage_Command::~TD_CreateStorage_Command() {
    }

    TDSC_STATUS_CODE_t TD_CreateStorage_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;

            if( TDS_TTLV_Tools::decode_TTLV_Unicode_String(stream_ptr, TD_TTLV_TAG_CONTAINERNAME, TD_TTLV_TYPE_UNICODESTRING, shift_length, _td_container_name) ) {
                stream_ptr += shift_length;

                if( TDS_TTLV_Tools::decode_TTLV_Container_Type(stream_ptr, shift_length, _td_container_type) ) {
                    return_code = TDSC_SUCCESS;
                }
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_CreateStorage_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {

                if( session->get_object_by_value(_td_container_name.c_str(), _td_container_name.length(), _td_container_id) == nullptr ) {
                    TD_Object * object = new TD_Container(_td_container_name.c_str(), _td_container_name.length());
                    if( object) {
                        _td_container_id = session->add_object(object);
                        if( _td_container_id.is_nil() ) return_code = TDSC_CONTAINER_CREATION_FAILED;
                        else {

                            std::string filename = default_storage_path + default_storage_prefix + "-"  + to_string(_td_container_id) + ".txt";
                            std::ofstream storage_file(filename, std::ofstream::out | std::ofstream::binary | std::ofstream::app);

                            (reinterpret_cast<TD_Container*>(object))->set_storage_filename(filename);
                            storage_file << _td_container_name << std::endl;
                            storage_file.close();
                        }
                    } else return_code = TDSC_GENERAL_FAILURE;

                } else return_code = TDSC_CONTAINER_NAME_ALREADY_EXISTS;
            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

    TD_DeleteStorage_Command::TD_DeleteStorage_Command() : TD_Command() {
        _response_id = TD_DELETESTORAGE_RSP;
    }

    TD_DeleteStorage_Command::~TD_DeleteStorage_Command() {
    }

    TDSC_STATUS_CODE_t TD_DeleteStorage_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        // Retrieving Session-Id
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Container_Id(stream_ptr, shift_length, _td_container_id) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_DeleteStorage_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {
                TD_Container * container =  reinterpret_cast<TD_Container*>(session->get_object_by_id(_td_container_id));
                if( container ) {
                    std::string filename = (reinterpret_cast<TD_Container *>(container))->get_storage_filename();

                    if( remove( filename.c_str() ) != 0 ) return_code = TDSC_GENERAL_FAILURE;
                    else {
                        return_code = session->remove_object_by_id(_td_container_id);
                    }

                } else return_code = TDSC_UNKNOWN_CONTAINER_ID;
            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

    TD_StoreData_Command::TD_StoreData_Command() : TD_Command() {
        _response_id = TD_STOREDATA_RSP;
    }

    TD_StoreData_Command::~TD_StoreData_Command() {
        if( _td_data.data ) delete [] _td_data.data;
    }

    TDSC_STATUS_CODE_t TD_StoreData_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        // Retrieving Session-Id
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Container_Id(stream_ptr, shift_length, _td_container_id) ) {
                stream_ptr += shift_length;
                if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_data) ) {
                    return_code = TDSC_SUCCESS;
                }
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_StoreData_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {
                TD_Object * container = session->get_object_by_id(_td_container_id);
                if( container && !container->is_root_object() ) {
                    TD_Object * object = new TD_Object(_td_data.data, _td_data.length);
                    if( object ) {
                        _td_object_id = (reinterpret_cast<TD_Container *>(container))->add_object(object);

                        if( _td_object_id.is_nil()  ) return_code = TDSC_OBJECT_CREATION_FAILED;
                        else {
                            std::fstream storage_file((reinterpret_cast<TD_Container *>(container))->get_storage_filename(), std::ofstream::out | std::ofstream::binary | std::ofstream::app);
                            storage_file << to_string(_td_object_id) << std::endl;
                            /*
                            Encoding the Storage data in base64 - in case the data would contain non printable characters
                            */
                            std::string base64_string = Botan::base64_encode(reinterpret_cast<const uint8_t *>(_td_data.data), reinterpret_cast<size_t>(_td_data.length));
                            storage_file << base64_string << std::endl;


                            
                            storage_file.close();
                        }

                    }  else return_code = TDSC_GENERAL_FAILURE;
                } else return_code = TDSC_UNKNOWN_CONTAINER_ID;

            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

    TD_GetValue_Command::TD_GetValue_Command() : TD_Command() {
        _response_id = TD_GETVALUE_RSP;
    }

    TD_GetValue_Command::~TD_GetValue_Command() {
    }

    TDSC_STATUS_CODE_t TD_GetValue_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        return TDSC_SUCCESS;
    }

    TDSC_STATUS_CODE_t TD_GetValue_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        return return_code;
    }

    TD_GetStorageValue_Command::TD_GetStorageValue_Command() : TD_Command() {
        _response_id = TD_GETSTORAGEVALUE_RSP;
    }

    TD_GetStorageValue_Command::~TD_GetStorageValue_Command() {
    }

    TDSC_STATUS_CODE_t TD_GetStorageValue_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        // Retrieving Session-Id
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Container_Id(stream_ptr, shift_length, _td_container_id) ) {
                stream_ptr += shift_length;
                if( TDS_TTLV_Tools::decode_TTLV_Object_Id(stream_ptr, shift_length, _td_object_id) ) {
                    return_code = TDSC_SUCCESS;
                }
            } else return_code = TDSC_UNKNOWN_CONTAINER_ID;
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_GetStorageValue_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();
        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {
                TD_Object * container = session->get_object_by_id(_td_container_id);
                if( container && !container->is_root_object() ) {
                    TD_Object * object = (reinterpret_cast<TD_Container *>(container))->get_object_by_id(_td_object_id);

                    if( ! object ) {
                        _td_data.data = nullptr;
                        _td_data.length = 0;
                        return_code = TDSC_UNKNOWN_OBJECT_ID;
                    } else {
                        _td_data.data = const_cast<char *>(object->get_blob());
                        _td_data.length = object->get_size();
                    }
                } else {
                    return_code = TDSC_UNKNOWN_CONTAINER_ID;
                }

            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

    TD_GetStorage_Command::TD_GetStorage_Command() : TD_Command() {
        _response_id = TD_GETSTORAGE_RSP;
    }

    TD_GetStorage_Command::~TD_GetStorage_Command() {
    }

    TDSC_STATUS_CODE_t TD_GetStorage_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;

            if( TDS_TTLV_Tools::decode_TTLV_Unicode_String(stream_ptr, TD_TTLV_TAG_CONTAINERNAME, TD_TTLV_TYPE_UNICODESTRING, shift_length, _td_container_name) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_GetStorage_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {

                TD_Object * container = session->get_object_by_value(_td_container_name.c_str(), _td_container_name.length(), _td_container_id);
                if( container == nullptr ) {
                    return_code = TDSC_UNKNOWN_CONTAINER_ID;

                    /* Let's search this container among saved containers on the filesystem
                       If a container with the correct container name exists, it is loaded
                       Warning : if multiple containers have the searched container's name, only the first one will be loaded
                    
                       1 - search for STO-...txt files
                       2 - open each STO-...txt file, and retrieve the first line for container's name
                       3 - if container's name match, then load the container in the current session
                          3.1 - container's uuid is documented in the STO-...txt
                          3.2 - iterate :
                             3.2.1 : read Object-Id (uuid)
                             3.2.2 : Object value (base64 encoded) 
                    */

                    for( auto &storage_path : boost::filesystem::directory_iterator(default_storage_path) ) {
                        
                        if( boost::filesystem::is_regular_file(storage_path.path()) ) {
                            std::string filename = storage_path.path().filename().string();
                            std::string full_filename = storage_path.path().string();

                            TD_Container * container = nullptr;
                            _td_container_id = nil_uuid();
                            bool container_initiated = false;

                            if( std::equal(default_storage_prefix.begin(), default_storage_prefix.end(), filename.begin() )) {
                                std::ifstream input_file(full_filename);
                                input_file.exceptions(std::ifstream::failbit|std::ifstream::badbit);
                                
                                if( input_file.is_open() ) {

                                    try {

                                        std::string container_name;
                                        getline(input_file, container_name);

                                        if( _td_container_name.compare(container_name) == 0 && input_file.good() ) {
                                            return_code = TDSC_SUCCESS;

                                            if( !container_initiated ) {
                                                container = new TD_Container();

                                                if( container ) {
                                                    container->set_storage_filename(full_filename); 
                                                    _td_container_id = session->add_object(container);
                                                        
                                                    if( _td_container_id.is_nil() ) {
                                                        return_code = TDSC_CONTAINER_CREATION_FAILED;
                                                        break;
                                                    } 

                                                    container->set_data(container_name.c_str(), container_name.length());
                                                    container_initiated = true;
                                                } else {
                                                    return_code = TDSC_CONTAINER_CREATION_FAILED;
                                                    break;
                                                }
                                            }

                                            
                                            while( input_file.peek() != EOF ) {

                                                std::string object_uuid_string;
                                                std::string object_value_encoded_string; 
                                                std::string object_value_decoded_string; 

                                                std::getline(input_file, object_uuid_string);
                                                std::getline(input_file, object_value_encoded_string);

                                                Botan::secure_vector<uint8_t> decode64_string = Botan::base64_decode(object_value_encoded_string);
                                                object_value_decoded_string.assign(decode64_string.begin(), decode64_string.end());

                                                TD_Object * new_object = new TD_Object(object_value_decoded_string.c_str(), object_value_decoded_string.length());
                                                container->add_object(object_uuid_string, new_object); 
                                            }
                                        }   

                                    } catch(const std::exception& ex) {
                                        if( !_td_container_id.is_nil() && container != nullptr ) {
                                            session->remove_object_by_id(_td_container_id);
                                        }
                                        return_code = TDSC_UNKNOWN_CONTAINER_ID;
                                        break;
                                    }

                                    if( input_file.is_open() ) input_file.close();
                                    if( return_code == TDSC_SUCCESS ) break;
                                }
                            }
                        }
                    }
                } else {
                    sto_logger->debug("TD_GetStorage_Command Found Container:{} {}", _td_container_name, to_string(_td_container_id));
                }
            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        if( _td_container_id.is_nil() ) return_code = TDSC_UNKNOWN_CONTAINER_ID;
        return return_code;
    }

    TD_Search_Command::TD_Search_Command() : TD_Command() {
        _response_id = TD_SEARCH_RSP;
    }

    TD_Search_Command::~TD_Search_Command() {
    }

    TDSC_STATUS_CODE_t TD_Search_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;

            if( TDS_TTLV_Tools::decode_TTLV_Container_Id(stream_ptr, shift_length, _td_container_id) ) {
                stream_ptr += shift_length;
                
                if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_data) ) {
                    return_code = TDSC_SUCCESS;
                }
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_Search_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();
        if( return_code == TDSC_SUCCESS) {
            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {
                TD_Object * container = session->get_object_by_id(_td_container_id);
                if( container && !container->is_root_object() ) {
                    _td_object_id = (reinterpret_cast<TD_Container *>(container))->get_object_id_by_value(_td_data);
                    if( _td_object_id == nil_uuid() ) {
                        return_code = TDSC_VALUE_NOT_FOUND;
                    } 
                }
            }
        }

        return return_code;
    }
    
}

