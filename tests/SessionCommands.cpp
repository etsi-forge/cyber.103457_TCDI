#include "SessionCommands.h"
#include "TDS_CType.h"
#include "TDS_Commands.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_Session_Commands.h"

bool CreateSession_Command(TDS::TDSC_SESSION_ID_t& the_session_id) {

    std::unique_ptr<TDS::TD_CreateSession_Command> the_command(new TDS::TD_CreateSession_Command());

    TDS::TDSC_STATUS_CODE_t returnCode = the_command->execute_command();

    the_session_id = the_command->get_session_id();

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool CloseSession_Command(TDS::TDSC_SESSION_ID_t& the_session_id) {

    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length = 0;
    TDS::TDSC_LENGTH_t shift_length;
    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_Command> the_command(new TDS::TD_CloseSession_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_CLOSESESSION_CMD, msg_ptr) ) {
        msg_length += sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            TDS::TDS_TTLV_Tools::dump_Command(msg, msg_length);

            TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
            the_command->set_message(sess_message);

            returnCode = the_command->execute_command();
        }
    }
    
    return ( returnCode ==  TDS::TDSC_SUCCESS );
}
