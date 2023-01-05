#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_Connection_Commands.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace TDS {

    auto cnxcmd_logger = spdlog::stdout_color_mt("cnx_cmd");    /*!< Connection Commands related spdlog Logger */

    /* TD_OpenConnectionCommand */

    TD_OpenConnection_Command::TD_OpenConnection_Command() : TD_Command() {
        _response_id = TD_OPENCONNECTION_RSP;
    }

    TD_OpenConnection_Command::~TD_OpenConnection_Command() {
    }

    TDSC_STATUS_CODE_t TD_OpenConnection_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        TDSC_LTD_ID_t           ltd_id;
        TDSC_LTD_ROLE_t         ltd_role;
        TDSC_CERT_COMMON_NAME_t certificate_CN;

        TDSC_NONCE_t nonce;
        TDSC_DATA_t data;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);
        // Retrieving LTD-Id, LTD-Role, CN, Nonce and DATA
        if( TDS_TTLV_Tools::decode_TTLV_Unicode_String(stream_ptr, TD_TTLV_TAG_LTDID, TD_TTLV_TYPE_UNICODESTRING, shift_length, ltd_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Unicode_String(stream_ptr, TD_TTLV_TAG_LTDROLE, TD_TTLV_TYPE_UNICODESTRING, shift_length, ltd_role) ) {
                stream_ptr += shift_length;
                if( TDS_TTLV_Tools::decode_TTLV_Unicode_String(stream_ptr, TD_TTLV_TAG_CN, TD_TTLV_TYPE_UNICODESTRING, shift_length, certificate_CN) ) {
                    stream_ptr += shift_length;
                    if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_NONCE, TD_TTLV_TYPE_BYTESTRING, shift_length, nonce) ) {
                        stream_ptr += shift_length;
                        if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, data) ) {

                            return_code = TD_Connection::get_connection()->set_connection_properties(ltd_id, ltd_role, certificate_CN, nonce, data); 
                            
                            if( return_code == TDSC_SUCCESS ) TD_Connection::get_connection()->get_container_id(_config_container_id);
                        }
                    }
                }
            }
        }

        // Cleanup allocations
        if( nonce.data ) delete [] nonce.data;
        if( data.data )  delete [] data.data;

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_OpenConnection_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        return return_code;
    }

    /* TD_CloseConnection_Command */

    TD_CloseConnection_Command::TD_CloseConnection_Command() : TD_Command() {
        _response_id = 0;
    }

    TD_CloseConnection_Command::~TD_CloseConnection_Command() {
    }

    TDSC_STATUS_CODE_t TD_CloseConnection_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = TDSC_SUCCESS;
        TD_Connection::get_connection()->close_connection();

        return return_code;
    }
}
