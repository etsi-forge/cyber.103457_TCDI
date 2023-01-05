#include "ObjectCommands.h"
#include "TDS_Commands.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Object_Commands.h"

bool CreateObject_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_OBJECT_ID_t& the_object_id) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_CreateObject_Command> the_command(new TDS::TD_CreateObject_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_CREATEOBJECT_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
            the_command->set_message(sess_message);
            returnCode = the_command->execute_command();
            if( returnCode == TDS::TDSC_SUCCESS ) the_command->get_object_id(the_object_id);
            else the_object_id = nil_uuid();
        }
    }

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool PutObjectValue_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_OBJECT_ID_t object_id, TDS::TDSC_DATA_t& data_bytestring) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_Command> the_command(new TDS::TD_PutObjectValue_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_PUTOBJECTVALUE_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Object_Id_TTLV(object_id, shift_length, msg_ptr + msg_length) ) {
                msg_length += shift_length;

                if( TDS::TDS_TTLV_Tools::encode_Byte_String_TTLV(TD_TTLV_TAG_DATA, data_bytestring.data, data_bytestring.length, shift_length, msg_ptr + msg_length) ) {
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

bool GetObjectValue_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_OBJECT_ID_t object_id, TDS::TDSC_DATA_t& object_value) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_GetObjectValue_Command> the_command(new TDS::TD_GetObjectValue_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_GETOBJECTVALUE_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Object_Id_TTLV(object_id, shift_length, msg_ptr + msg_length) ) {
                msg_length += shift_length;

                TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                the_command->set_message(sess_message);
                TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                returnCode = the_command->execute_command();
                if( returnCode == TDS::TDSC_SUCCESS ) the_command->get_object_value(object_value);
                else {
                    object_value.length = 0;
                    object_value.data = nullptr;
                }
            }
        }
    }
    
    return ( returnCode == TDS::TDSC_SUCCESS );
}
