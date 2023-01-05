#include "ArchiveCommands.h"
#include "TDS_CType.h"
#include "TDS_Commands.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Archive_Commands.h"

bool CreateArchive_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_CreateArchive_Command> the_command(new TDS::TD_CreateArchive_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_CREATEARCHIVE_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Container_Type_TTLV(TD_TTLV_TAG_PERMANENTFILE, msg_ptr + msg_length) ) {
                msg_length += sizeof(TDS::TDSC_TAG_t) + sizeof(TDS::TDSC_TYPE_t) + sizeof(TDS::TDSC_LENGTH_t) + sizeof(TDS::TDSC_CONTAINER_t);

                TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                the_command->set_message(sess_message);

                TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                returnCode = the_command->execute_command();
                if( returnCode == TDS::TDSC_SUCCESS )the_command->get_container_id(the_container_id);
                else the_container_id = nil_uuid();
            }
        }
    }

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool Archive_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id, std::string& data_string) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_Command> the_command(new TDS::TD_Archive_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_ARCHIVE_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Container_Id_TTLV(the_container_id, shift_length, msg_ptr + msg_length) ) {
                msg_length += shift_length;

                if( TDS::TDS_TTLV_Tools::encode_Byte_String_TTLV(TD_TTLV_TAG_DATA, data_string.c_str(), data_string.length(), shift_length, msg_ptr + msg_length) ) {
                    msg_length += shift_length;

                    TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                    the_command->set_message(sess_message);

                    TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                    returnCode = the_command->execute_command();
                }
            }
        }
    }

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool CloseArchive_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_CONTAINER_ID_t& the_container_id) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_Command> the_command(new TDS::TD_CloseArchive_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_CLOSEARCHIVE_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Container_Id_TTLV(the_container_id, shift_length, msg_ptr + msg_length) ) {
                msg_length += shift_length;

                TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                the_command->set_message(sess_message);

                TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                returnCode = the_command->execute_command();
            }
        }
    }
    
    return ( returnCode == TDS::TDSC_SUCCESS );
}
