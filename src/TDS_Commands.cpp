#include "TDS_Commands.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace TDS {

    auto cmd_logger = spdlog::stdout_color_mt("command");       /*!< Commands related spdlog Logger */

/*
TD_Message
*/

    TD_Message::TD_Message(char * message_stream, uint64_t message_length) {
        if( _message_stream ) delete [] _message_stream;
        _message_length = message_length;
        _message_stream = new char[_message_length];
        memcpy(_message_stream, message_stream, _message_length);
    }

    TD_Message::~TD_Message() {
        if( _message_stream ) delete [] _message_stream;
        _message_stream = nullptr;
        _message_length = UINT64_C(0);
    }

/*
TD_Command
*/

    TD_Command::TD_Command() {
        memset(&_session_id, 0x00, sizeof(TDSC_SESSION_ID_t) );
    }

    TD_Command::TD_Command(TDSC_SESSION_ID_t session_id) {
        _session_id = session_id;
    }

    TD_Command::~TD_Command() {
        if( _message ) delete _message;
    }

    void TD_Command::set_message(TD_Message * msg) {
        _message = msg;
    }

}
