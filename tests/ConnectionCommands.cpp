#include "ConnectionCommands.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Commands.h"
#include "TDS_Connection_Commands.h"

bool OpenConnection_command(std::string& LTD_Id_string, std::string& LTD_Role_string, std::string& LTD_CN_string, TDS::TDSC_NONCE_t& LTD_Nonce_ByteString, TDS::TDSC_DATA_t& LTD_Data_ByteString) {

    TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
    char msg[1024];
    memset(msg,0x0,1024);
    TDS::TDSC_LENGTH_t msg_length;
    TDS::TDSC_LENGTH_t shift_length;

    char * msg_ptr = &msg[0];

    std::unique_ptr<TDS::TD_Command> the_command(new TDS::TD_OpenConnection_Command());

    if( TDS::TDS_TTLV_Tools::encode_Command_Type(TD_OPENCONNECTION_CMD, msg_ptr) ) {
        msg_length = sizeof(TDS::TDSC_COMMAND_t);

        if( TDS::TDS_TTLV_Tools::encode_Unicode_String_TTLV(TD_TTLV_TAG_LTDID, LTD_Id_string, shift_length, msg_ptr + msg_length) ) {
            msg_length += shift_length;

            if( TDS::TDS_TTLV_Tools::encode_Unicode_String_TTLV(TD_TTLV_TAG_LTDROLE, LTD_Role_string, shift_length, msg_ptr + msg_length) ) {
                msg_length += shift_length;

                if( TDS::TDS_TTLV_Tools::encode_Unicode_String_TTLV(TD_TTLV_TAG_CN, LTD_CN_string, shift_length, msg_ptr + msg_length) ) {
                    msg_length += shift_length;

                    if( TDS::TDS_TTLV_Tools::encode_Byte_String_TTLV(TD_TTLV_TAG_NONCE, LTD_Nonce_ByteString.data, LTD_Nonce_ByteString.length, shift_length, msg_ptr + msg_length) ) {
                        msg_length += shift_length;

                        if( TDS::TDS_TTLV_Tools::encode_Byte_String_TTLV(TD_TTLV_TAG_DATA, LTD_Data_ByteString.data, LTD_Data_ByteString.length, shift_length, msg_ptr + msg_length) ) {
                            msg_length += shift_length;

                            TDS::TDS_TTLV_Tools::dump_Command(msg, msg_length);

                            TDS::TD_Message * ltd_message = new TDS::TD_Message(msg, msg_length);
                            the_command->set_message(ltd_message);

                            returnCode = the_command->execute_command();
                        }
                    }
                }
            }
        }
    }

    return ( returnCode == TDS::TDSC_SUCCESS );
}

bool CloseConnection_Command() {

    std::unique_ptr<TDS::TD_Command> the_command(new TDS::TD_CloseConnection_Command());
    TDS::TDSC_STATUS_CODE_t returnCode = the_command->execute_command();

    return ( returnCode ==  TDS::TDSC_SUCCESS );
}
