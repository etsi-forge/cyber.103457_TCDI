#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Session.h"
#include "TDS_Connection.h"
#include "TDS_Session_Commands.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

namespace TDS {

    auto ses_logger = spdlog::stdout_color_mt("ses_cmd");   /*!< Session Commands related spdlog Logger */

    /* TD_CreateSessionCommand */

    TD_CreateSession_Command::TD_CreateSession_Command() : TD_Command() {
        _response_id = TD_CREATESESSION_RSP;
    }

    TD_CreateSession_Command::~TD_CreateSession_Command() {
    }

    TDSC_STATUS_CODE_t TD_CreateSession_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;

        TD_Session * new_session = new TD_Session();
        if( TD_Connection::get_connection()->get_session_manager() ) {
            // Add session to the session manager */
            if( TD_Connection::get_connection()->get_session_manager()->can_add_new_session() ) {
                if( TD_Connection::get_connection()->get_session_manager()->add_session(new_session->get_session_id(), new_session) ) {
                    return_code = TDSC_SUCCESS;
                    _session_id = new_session->get_session_id();
                }
            } else {
                return_code = TDSC_TOO_MANY_EXISTING_SESSIONS;

            }
        }
        
        return return_code;
    }

    TD_CloseSession_Command::TD_CloseSession_Command() : TD_Command() {
        _response_id = TD_CLOSESESSION_RSP;
    }

    TD_CloseSession_Command::~TD_CloseSession_Command() {
    }

    TDSC_STATUS_CODE_t TD_CloseSession_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;
        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            return_code = TDSC_SUCCESS;
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_CloseSession_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS ) {
            return_code = TD_Connection::get_connection()->get_session_manager()->remove_session(_session_id);
        }

        return return_code;
    }

}
