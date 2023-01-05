#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Object_Commands.h"
#include "TDS_Connection.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <boost/uuid/uuid_io.hpp>

namespace TDS {

    auto objcmd_logger = spdlog::stdout_color_mt("object_cmd"); /*!< Object Commands related spdlog Logger */

    TD_CreateObject_Command::TD_CreateObject_Command() : TD_Command() {
        _response_id = TD_CREATEOBJECT_RSP;
    }

    TD_CreateObject_Command::~TD_CreateObject_Command() {
    }

    TDSC_STATUS_CODE_t TD_CreateObject_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            return_code = TDSC_SUCCESS;
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_CreateObject_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session != nullptr ) {
                TD_Object * object = new TD_Object();
                _td_object_id = session->add_object(object);
                if( _td_object_id.is_nil() ) return_code = TDSC_OBJECT_CREATION_FAILED;
            } else {
                _td_object_id = nil_uuid();;
                return_code = TDSC_UNKNOWN_SESSION_ID;
            }
        }

        return return_code;
    }

    /* TD_GetObjectValue_Command */

    TD_GetObjectValue_Command::TD_GetObjectValue_Command() : TD_Command() {
        _response_id = TD_GETOBJECTVALUE_RSP;
    }

    TD_GetObjectValue_Command::~TD_GetObjectValue_Command() {
    }

    TDSC_STATUS_CODE_t TD_GetObjectValue_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length = 0;
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Object_Id(stream_ptr, shift_length, _td_object_id) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_GetObjectValue_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {
            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);

            if( session != nullptr ) {
                return_code = session->get_object_value(_td_object_id, _td_data);
            } else {
                return_code = TDSC_UNKNOWN_SESSION_ID;
            }
        }

        return return_code;
    }

    /* TD_PutObjectValue_Command */

    TD_PutObjectValue_Command::TD_PutObjectValue_Command() : TD_Command() {
        _response_id = TD_PUTOBJECTVALUE_RSP;
    }

    TD_PutObjectValue_Command::~TD_PutObjectValue_Command() {
        if( _td_data.data ) delete [] _td_data.data;
    }

    TDSC_STATUS_CODE_t TD_PutObjectValue_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        TDSC_LENGTH_t shift_length = 0;
        uint64_t msg_length = _message->get_length()-1;
        TDSC_LENGTH_t total_used = 0;

        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);
        total_used++;
        
        std::vector<uint8_t> vec(stream_ptr, stream_ptr + msg_length);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            total_used += shift_length;

            if( TDS_TTLV_Tools::decode_TTLV_Object_Id(stream_ptr, shift_length, _td_object_id) ) {
                stream_ptr += shift_length;
                total_used += shift_length;

                if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_data) ) {
                    return_code = TDSC_SUCCESS;
                }
            }

        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_PutObjectValue_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS) {
            
            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session != nullptr ) {
                    return_code = session->set_object_value(_td_object_id, _td_data);
            } else {
                return_code = TDSC_UNKNOWN_SESSION_ID;
            }
        }

        return return_code;
    }
    
}

