#include <chrono>
#include <fstream>

#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_Archive_Commands.h"

#include <botan/base64.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace TDS {

    auto arch_logger = spdlog::stdout_color_mt("arch_cmd");     /*!< Archive Commands related spdlog Logger */
    const std::string default_archive_path = "/tmp/";           /*!< Default root path to store Archive files */ 
    const std::string default_archive_prefix = "ARCH";          /*!< Default archive prefix */

/*
TD_CreateArchive_Command
*/
    TD_CreateArchive_Command::TD_CreateArchive_Command() : TD_Command() {
        _response_id = TD_CREATEARCHIVE_RSP;
    }

    TD_CreateArchive_Command::~TD_CreateArchive_Command() {
    }

    TDSC_STATUS_CODE_t TD_CreateArchive_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Container_Type(stream_ptr, shift_length, _td_container_type) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_CreateArchive_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {
            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);

            if( session ) {

                std::string filename = default_archive_path + default_archive_prefix + "-" + to_string(_session_id) + ".txt";
                TD_Object * object = new TD_Object(filename.c_str(), filename.length());
                _td_object_id = session->add_object(object);
                if( _td_object_id.is_nil() ) return_code = TDSC_OBJECT_CREATION_FAILED;
                else {
                    std::ofstream archive_file(filename, std::ofstream::out | std::ofstream::binary | std::ofstream::app);
                    archive_file.close();          
                }          
            } else {
                return_code = TDSC_UNKNOWN_SESSION_ID;
            }
        }

        return return_code;
    }

/*
TD_CloseArchive_Command
*/
    TD_CloseArchive_Command::TD_CloseArchive_Command() : TD_Command() {
        _response_id = TD_CLOSEARCHIVE_RSP;
    }

    TD_CloseArchive_Command::~TD_CloseArchive_Command() {
    }

    TDSC_STATUS_CODE_t TD_CloseArchive_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;
        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Container_Id(stream_ptr, shift_length, _td_object_id) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_CloseArchive_Command::execute_command()  {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {
                return_code = session->remove_object_by_id(_td_object_id);
            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

/*
TD_Archive_Command
*/
    TD_Archive_Command::TD_Archive_Command() : TD_Command() {
        _response_id = TD_ARCHIVE_RSP;
    }

    TD_Archive_Command::~TD_Archive_Command() {
        if( _td_data.data ) delete [] _td_data.data;
    }

    TDSC_STATUS_CODE_t TD_Archive_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Container_Id(stream_ptr, shift_length, _td_object_id) ) {
                stream_ptr += shift_length;
                if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_data) ) {
                    return_code = TDSC_SUCCESS;
                }
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_Archive_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {
            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);

            if( session ) {
                TDSC_DATA_t t_data;
                return_code = session->get_object_value(_td_object_id, t_data);
                if( return_code == TDSC_SUCCESS ) {
                    std::string filename(t_data.data, t_data.length);
                    std::fstream archive_file(filename, std::ofstream::out | std::ofstream::binary | std::ofstream::app);
                    /*
                    Encoding the Archive data in base64 - in case the data would contain non printable characters
                    */
                    std::string base64_string = Botan::base64_encode(reinterpret_cast<const uint8_t *>(_td_data.data), reinterpret_cast<size_t>(_td_data.length));
                    archive_file << base64_string << std::endl;
                    archive_file.close();
                } else {
                    return_code = TDSC_UNKNOWN_ARCHIVE_ID;
                }
            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }
    
}

