#include "CryptoCommands.h"
#include "TDS_Commands.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Crypto_Commands.h"

bool GetRandom_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_SIZE_IN_BYTES_t size_in_byte, TDS::TDSC_OBJECT_ID_t& object_id) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_GetRandom_Command> the_command(new TDS::TD_GetRandom_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_GETRANDOM_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_SizeInBytes_TTLV(size_in_byte, msg_ptr + msg_length) ) {
                msg_length += sizeof(TDS::TDSC_TAG_t) + sizeof(TDS::TDSC_TYPE_t) + sizeof(TDS::TDSC_LENGTH_t) + sizeof(TDS::TDSC_SIZE_IN_BYTES_t);

                TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                the_command->set_message(sess_message);

                TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                returnCode = the_command->execute_command();
                if( returnCode == TDS::TDSC_SUCCESS ) the_command->get_object_id(object_id);
                else object_id = nil_uuid();
            }
        }
    }

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool GetTrustedTimestamping_Command(TDS::TDSC_SESSION_ID_t& the_session_id, TDS::TDSC_OBJECT_ID_t& object_id) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_GetTrustedTimeStamping_Command> the_command(new TDS::TD_GetTrustedTimeStamping_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_GETTRUSTEDTIMESTAMP_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;
            std::string data_string = "Data ByteString";

            if( TDS::TDS_TTLV_Tools::encode_Byte_String_TTLV(TD_TTLV_TAG_DATA, data_string.c_str(), data_string.length(), shift_length, msg_ptr + msg_length) ) {
                msg_length += shift_length;

                TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                the_command->set_message(sess_message);

                TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                returnCode = the_command->execute_command();
                if( returnCode == TDS::TDSC_SUCCESS ) the_command->get_object_id(object_id);
                else object_id = nil_uuid();
            }
        }
    }

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool GetEncryptionKey_Command(TDS::TDSC_SESSION_ID_t & the_session_id, TDS::TDSC_KEY_TYPE_t key_type, TDS::TDSC_OBJECT_ID_t& object_id) {
    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_GenerateEncryptionKey_Command> the_command(new TDS::TD_GenerateEncryptionKey_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_GENERATEENCRYPTIONKEY_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Session_Id_TTLV(the_session_id, shift_length,  msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Key_Type_TTLV(key_type, msg_ptr + msg_length) ) {
                msg_length += sizeof(TDS::TDSC_TAG_t) + sizeof(TDS::TDSC_TYPE_t) + sizeof(TDS::TDSC_LENGTH_t) + sizeof(TDS::TDSC_KEY_TYPE_t);

                TDS::TD_Message * sess_message = new TDS::TD_Message(msg, msg_length);
                the_command->set_message(sess_message);

                TDS::TDS_TTLV_Tools::dump_Command(msg,msg_length);
                returnCode = the_command->execute_command();
                if( returnCode == TDS::TDSC_SUCCESS ) the_command->get_object_id(object_id);
                else object_id = nil_uuid();
            }
        }
    }
    
    return ( returnCode == TDS::TDSC_SUCCESS );
}

