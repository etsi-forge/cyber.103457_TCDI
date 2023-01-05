#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

namespace TDS {

    boost::uuids::random_generator TDS_TTLV_Tools::_uuid_generator; /*!< boost:uuid generator*/

    boost::uuids::uuid TDS_TTLV_Tools::gen_uuid() {
    	return _uuid_generator();
    }

    auto ttlv_logger = spdlog::stdout_color_mt("ttlv");             /*!< TTLV related spdlog Logger */

    /*
    TD_TTLV_Utils decoding from TTLV
    */

    bool TDS_TTLV_Tools::_decode_TTLV_uint8(char * msg_string, uint8_t& place_holder) {

        return ( memcpy(&place_holder, msg_string, sizeof(uint8_t)) != nullptr );
    }

    bool TDS_TTLV_Tools::_decode_TTLV_uint16(char * msg_string, uint16_t& place_holder) {

        return ( memcpy(&place_holder, msg_string, sizeof(uint16_t)) != nullptr );
    }

    bool TDS_TTLV_Tools::_decode_TTLV_uint64(char * msg_string, uint64_t& place_holder) {

        return ( memcpy(&place_holder, msg_string, sizeof(uint64_t)) != nullptr );
    }

    bool TDS_TTLV_Tools::decode_TTLV_Tag(char * msg_string, TDSC_TAG_t& placeholder) {

        return _decode_TTLV_uint8(msg_string, placeholder);
    }

    bool TDS_TTLV_Tools::decode_TTLV_Type(char * msg_string, TDSC_TYPE_t& placeholder) {

        return _decode_TTLV_uint16(msg_string, placeholder);
    }

    bool TDS_TTLV_Tools::decode_TTLV_Length(char * msg_string, TDSC_LENGTH_t& placeholder) {

        return _decode_TTLV_uint64(msg_string, placeholder);
    }

    bool TDS_TTLV_Tools::_decode_TTLV_bytestring(char * msg_string, bytestring& placeholder) {
        placeholder.data = new char[placeholder.length];

        return ( memcpy(&placeholder.data[0], msg_string, placeholder.length) != nullptr );
    }

    bool TDS_TTLV_Tools::_decode_TTLV_string(char * msg_string, uint64_t length, std::string& placeholder) {
        bool return_code = true;

        char * temp_placeholder= new char[length+1];
        temp_placeholder[length] = 0x00;
        return_code = (memcpy(&temp_placeholder[0], msg_string, length) != nullptr);
        if( return_code ) placeholder = temp_placeholder;
        else placeholder = "";
        delete [] temp_placeholder;

        return return_code;
    }

    void TDS_TTLV_Tools::_bytestring_to_uuid(bytestring& placeholder_bytestring , boost::uuids::uuid& placeholder) {
        std::string uuid_string(placeholder_bytestring.data, placeholder_bytestring.length);
        boost::uuids::string_generator gen;
        placeholder = gen(uuid_string);
    }

    /*
    TD_TTLV_Utils encoding to TTLV
    */

    bool TDS_TTLV_Tools::_encode_uint8_TTLV(const uint8_t value, char * placeholder) {

        return ( memcpy(placeholder, reinterpret_cast<void*>(const_cast<uint8_t*>(&value)), sizeof(uint8_t)) != nullptr );
    }

    bool TDS_TTLV_Tools::_encode_uint16_TTLV(const uint16_t value, char * placeholder) {

        return ( memcpy(placeholder, reinterpret_cast<void*>(const_cast<uint16_t*>(&value)), sizeof(uint16_t)) != nullptr );
    }

    bool TDS_TTLV_Tools::_encode_uint64_TTLV(const uint64_t value, char * placeholder) {

        return ( memcpy(placeholder, reinterpret_cast<void*>(const_cast<uint64_t*>(&value)), sizeof(uint64_t)) != nullptr );
    }

    bool TDS_TTLV_Tools::encode_Tag_TTLV(const TDSC_TAG_t tag_value, char * placeholder) {

        return _encode_uint8_TTLV(tag_value, placeholder);
    }

    bool TDS_TTLV_Tools::encode_Type_TTLV(const TDSC_TYPE_t type_value, char * placeholder) {

        return _encode_uint16_TTLV(type_value, placeholder);
    }

    bool TDS_TTLV_Tools::encode_Length_TTLV(const TDSC_LENGTH_t length_value, char * placeholder) {

        return _encode_uint64_TTLV(length_value, placeholder);
    }

    bool TDS_TTLV_Tools::_encode_bytestring_TTLV(const char * byte_string, uint64_t length, char * placeholder) {

        return ( memcpy(placeholder+sizeof(uint64_t), byte_string, length) != nullptr );
    }

    bool TDS_TTLV_Tools::_encode_string_TTLV(std::string & estring, char * placeholder) {

        return ( _encode_bytestring_TTLV(estring.c_str(),estring.length(),placeholder) );
    }

    /*
        extract_TTLV_Unicode_String
    */

    bool TDS_TTLV_Tools::decode_TTLV_Unicode_String(char * msg_string, const TDSC_TAG_t ttlv_tag, const TDSC_TYPE_t ttlv_type, TDSC_LENGTH_t& shift_length, std::string& placeholder) {
        bool return_code = false;
        TDSC_TAG_t  t_tag;

        shift_length = 0;
        if( TDS_TTLV_Tools::decode_TTLV_Tag(msg_string, t_tag) ) {
            msg_string   += sizeof(TDSC_TAG_t);
            shift_length += sizeof(TDSC_TAG_t);

            TDSC_TYPE_t t_type;
            if( (t_tag == ttlv_tag) && TDS_TTLV_Tools::decode_TTLV_Type(msg_string, t_type) ) {
                msg_string   += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                TDSC_LENGTH_t t_length;
                if( (t_type == ttlv_type) && TDS_TTLV_Tools::decode_TTLV_Length(msg_string, t_length) ) {
                    msg_string   += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    if( t_length > 0 ) {
                        if( (t_length < placeholder.max_size()) && TDS_TTLV_Tools::_decode_TTLV_string(msg_string, t_length, placeholder) ) {
                            shift_length += t_length;
                            return_code = true;
                        }
                    } else {
                            return_code = true;
                            placeholder = "";
                    }
                }
            }
        }

        return return_code;
    }

    /*
        extract_TTLV_Byte_String
    */

    bool TDS_TTLV_Tools::decode_TTLV_Byte_String(char * msg_string, const uint8_t ttlv_tag, const uint16_t ttlv_type, TDSC_LENGTH_t& shift_length, bytestring& placeholder) {
        bool return_code = false;
        TDSC_TAG_t  t_tag;
        TDSC_TYPE_t t_type;
        TDSC_LENGTH_t t_length;
        
        shift_length = 0;

        ttlv_logger->debug("+---------------------------------------+");

        if( TDS_TTLV_Tools::decode_TTLV_Tag(msg_string, t_tag) ) {

            msg_string   += sizeof(TDSC_TAG_t);
            shift_length += sizeof(TDSC_TAG_t);

            ttlv_logger->debug("decode_TTLV_Byte_String TAG : [{}][{}][{}]", t_tag, TDS_TTLV_Tools::TAG_to_string(t_tag), TDS_TTLV_Tools::TAG_to_string(ttlv_tag));

            std::vector<uint8_t> vec(msg_string, msg_string + 15);
            ttlv_logger->debug("TTLV_Byte_String : [{}] [{:n} ]", 15, spdlog::to_hex(std::begin(vec), std::begin(vec) + 15));

            if( (t_tag == ttlv_tag) && TDS_TTLV_Tools::decode_TTLV_Type(msg_string, t_type) ) {

                ttlv_logger->debug("decode_TTLV_Byte_String TYPE : [{}][{}][{}]", t_type, TDS_TTLV_Tools::TYPE_to_string(t_type), TDS_TTLV_Tools::TYPE_to_string(ttlv_type));

                msg_string   += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t); 
                
                if( (t_type == ttlv_type) && TDS_TTLV_Tools::decode_TTLV_Length(msg_string, t_length) ) {

                    msg_string   += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    std::vector<uint8_t> vec(msg_string, msg_string + 15);
                    ttlv_logger->debug("TTLV_Byte_String Next 15 Remaining : [{}]  [{:n} ]", t_length, spdlog::to_hex(std::begin(vec), std::begin(vec) + 15));
                    
                    ttlv_logger->debug("decode_TTLV_Length used length [{}]", shift_length);

                    // t_length can be 0
                    placeholder.length = t_length;

                    if( TDS_TTLV_Tools::_decode_TTLV_bytestring(msg_string, placeholder) ) {

                        shift_length += t_length;
                        return_code = true;
                        ttlv_logger->debug("decode_TTLV_Length finished. Used length [{}]", shift_length);
                    } 
                }
            }
        }
        ttlv_logger->debug("+---------------------------------------+");

        return return_code;
    }

    /*
        extract_TTLV_Object_Id
    */

    bool TDS_TTLV_Tools::decode_TTLV_Object_Id(char * msg_string, TDSC_LENGTH_t& shift_length, TDSC_OBJECT_ID_t& placeholder) {
        bool return_code = false;
        TDSC_LENGTH_t t_length = 0;
        bytestring t_object_id_bytestring;

        if( TDS_TTLV_Tools::decode_TTLV_Byte_String(msg_string, TD_TTLV_TAG_OBJECTID, TD_TTLV_TYPE_UUID, t_length, t_object_id_bytestring) ) {
                shift_length = t_length;
                _bytestring_to_uuid(t_object_id_bytestring , placeholder);
                return_code = true;
        }

        return return_code;
    }

    /*
        extract_TTLV_Session_Id
    */

    bool TDS_TTLV_Tools::decode_TTLV_Session_Id(char * msg_string, TDSC_LENGTH_t& shift_length, TDSC_SESSION_ID_t& placeholder) {
        bool return_code = false;
        TDSC_LENGTH_t t_length = 0;
        bytestring t_session_id_bytestring;

        if( TDS_TTLV_Tools::decode_TTLV_Byte_String(msg_string, TD_TTLV_TAG_SESSIONID, TD_TTLV_TYPE_UUID, t_length, t_session_id_bytestring) ) {
                shift_length = t_length;
                _bytestring_to_uuid(t_session_id_bytestring , placeholder);
                return_code = true;
        }

        return return_code;
    }


    /*
        extract_TTLV_Container_Id
    */

    bool TDS_TTLV_Tools::decode_TTLV_Container_Id(char * msg_string, uint64_t& shift_length, TDSC_CONTAINER_ID_t& placeholder) {
        bool return_code = false;
        uint64_t t_length = 0;
        bytestring t_container_id_bytestring;

        if( TDS_TTLV_Tools::decode_TTLV_Byte_String(msg_string, TD_TTLV_TAG_CONTAINERID, TD_TTLV_TYPE_UUID, t_length, t_container_id_bytestring) ) {
                shift_length = t_length;
                _bytestring_to_uuid(t_container_id_bytestring , placeholder);
                return_code = true;
        }

        return return_code;
    }

    /*
        extract_TTLV_Container_Type
    */

    bool TDS_TTLV_Tools::decode_TTLV_Container_Type(char * msg_string, uint64_t& shift_length, TDSC_CONTAINER_t& placeholder) {
        bool return_code = false;
        TDSC_TAG_t  t_tag;
        TDSC_TYPE_t t_type;
        TDSC_LENGTH_t t_length;

        shift_length = 0;

        if( TDS_TTLV_Tools::decode_TTLV_Tag(msg_string, t_tag) ) {

            msg_string   += sizeof(TDSC_TAG_t);
            shift_length += sizeof(TDSC_TAG_t);

            if( (t_tag == TD_TTLV_TAG_CONTAINERTYPE) && TDS_TTLV_Tools::decode_TTLV_Type(msg_string, t_type) ) {

                msg_string   += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                if( (t_type == TD_TTLV_TYPE_SYMBOL) && TDS_TTLV_Tools::decode_TTLV_Length(msg_string, t_length) ) {

                    msg_string   += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    // t_length can be 0
                    uint8_t value;
                    if( TDS_TTLV_Tools::_decode_TTLV_uint8(msg_string, value) ) {

                        memcpy(&placeholder , &value, sizeof(TDSC_CONTAINER_t));
                        shift_length += sizeof(TDSC_CONTAINER_t);
                        return_code = true;
                    }
                }
            }
        }

        return return_code;
    }

    /*
        extract_TTLV_Key_Type
    */
    bool TDS_TTLV_Tools::decode_TTLV_Key_Type(char * msg_string, uint64_t& shift_length, TDSC_KEY_TYPE_t& placeholder) {
        bool return_code = false;
        TDSC_TAG_t  t_tag;
        TDSC_TYPE_t t_type;
        TDSC_LENGTH_t t_length;

        shift_length = 0;

        uint8_t value;

        if( TDS_TTLV_Tools::decode_TTLV_Tag(msg_string, t_tag) ) {

            msg_string   += sizeof(TDSC_TAG_t);
            shift_length += sizeof(TDSC_TAG_t);

            if( (t_tag == TD_TTLV_TAG_KEYTYPE) && TDS_TTLV_Tools::decode_TTLV_Type(msg_string, t_type) ) {

                msg_string   += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                if( (t_type == TD_TTLV_TYPE_SYMBOL) && TDS_TTLV_Tools::decode_TTLV_Length(msg_string, t_length) ) {

                    msg_string   += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    // t_length can be 0
                    if( TDS_TTLV_Tools::_decode_TTLV_uint8(msg_string, value) ) {

                        memcpy(&placeholder, &value, sizeof(TDSC_KEY_TYPE_t));
                        shift_length += sizeof(TDSC_KEY_TYPE_t);
                        return_code = true;
                    }
                }
            }
        }

        return return_code;
    }

    /*
        extract_TTLV_SizeInBytes
    */

    bool TDS_TTLV_Tools::decode_TTLV_SizeInBytes(char * msg_string, uint64_t& shift_length, TDSC_SIZE_IN_BYTES_t& placeholder) {
        bool return_code = false;
        TDSC_TAG_t  t_tag;
        TDSC_TYPE_t t_type;
        TDSC_LENGTH_t t_length;

        shift_length = 0;

        if( TDS_TTLV_Tools::decode_TTLV_Tag(msg_string, t_tag) ) {

            msg_string   += sizeof(TDSC_TAG_t);
            shift_length += sizeof(TDSC_TAG_t);

            if( (t_tag == TD_TTLV_TAG_SIZEINBYTES) && TDS_TTLV_Tools::decode_TTLV_Type(msg_string, t_type) ) {

                msg_string   += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                if( (t_type == TD_TTLV_TYPE_INTEGER) && TDS_TTLV_Tools::decode_TTLV_Length(msg_string, t_length) ) {

                    msg_string   += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    uint64_t value;
                    if( TDS_TTLV_Tools::_decode_TTLV_uint64(msg_string, value) ) {

                        memcpy(&placeholder, &value, sizeof(TDSC_SIZE_IN_BYTES_t));
                        shift_length += sizeof(TDSC_SIZE_IN_BYTES_t);
                        return_code  = true;
                    }
                }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Byte_String_TTLV(const TDSC_TAG_t tag_name,  const char * byte_string, const uint64_t msg_length, TDSC_LENGTH_t& shift_length, char * placeholder) {
        bool return_code = false;

        TDSC_TYPE_t ttlv_type = TD_TTLV_TYPE_BYTESTRING;

        if( memcpy(placeholder, &tag_name, sizeof(TDSC_TAG_t)) ) {
            placeholder += sizeof(TDSC_TAG_t);
            shift_length = sizeof(TDSC_TAG_t);

            if( memcpy(placeholder, &ttlv_type, sizeof(TDSC_TYPE_t)) ) {
                placeholder += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                if( memcpy(placeholder, &msg_length, sizeof(TDSC_LENGTH_t)) ) {
                    placeholder += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    if( memcpy(placeholder, byte_string, msg_length) ) {
                        shift_length += msg_length;
                        return_code = true;
                   }
                }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_UUID_TTLV(const TDSC_TAG_t tag_name,  const char * byte_string, const uint64_t msg_length, TDSC_LENGTH_t& shift_length, char * placeholder) {
        bool return_code = false;

        TDSC_TYPE_t ttlv_type = TD_TTLV_TYPE_UUID;

        if( memcpy(placeholder, &tag_name, sizeof(TDSC_TAG_t)) ) {
            placeholder += sizeof(TDSC_TAG_t);
            shift_length = sizeof(TDSC_TAG_t);

            if( memcpy(placeholder, &ttlv_type, sizeof(TDSC_TYPE_t)) ) {
                placeholder += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                if( memcpy(placeholder, &msg_length, sizeof(TDSC_LENGTH_t)) ) {
                    placeholder += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    if( memcpy(placeholder, byte_string, msg_length) ) {
                        shift_length += msg_length;
                        return_code = true;
                   }
                }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Unicode_String_TTLV(const TDSC_TAG_t tag_name, const std::string& unicode_string, TDSC_LENGTH_t& shift_length, char * placeholder) {
        bool return_code = false;
        TDSC_LENGTH_t string_length = unicode_string.length();
        TDSC_TYPE_t ttlv_type = TD_TTLV_TYPE_UNICODESTRING;

        if( memcpy(placeholder, &tag_name, sizeof(TDSC_TAG_t)) ) {
            placeholder += sizeof(TDSC_TAG_t);
            shift_length = sizeof(TDSC_TAG_t);

            if( memcpy(placeholder, &ttlv_type, sizeof(TDSC_TYPE_t)) ) {
                placeholder += sizeof(TDSC_TYPE_t);
                shift_length += sizeof(TDSC_TYPE_t);

                if( memcpy(placeholder, &string_length, sizeof(TDSC_LENGTH_t)) ) {
                    placeholder += sizeof(TDSC_LENGTH_t);
                    shift_length += sizeof(TDSC_LENGTH_t);

                    if( memcpy(placeholder, unicode_string.c_str(), string_length) ) {
                        shift_length += string_length;
                        return_code = true;
                    }
                }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Session_Id_TTLV(const TDSC_SESSION_ID_t& session_id, TDSC_LENGTH_t& shift_length,  char * placeholder) {
        bool return_code = false;
        std::string session_id_string = to_string(session_id);

        return_code = encode_UUID_TTLV(TD_TTLV_TAG_SESSIONID, session_id_string.c_str(), session_id_string.length(), shift_length, placeholder);

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Object_Id_TTLV(const TDSC_OBJECT_ID_t& object_id, TDSC_LENGTH_t& shift_length,  char * placeholder) {
        bool return_code = false;
        std::string object_id_string = to_string(object_id);

        return_code = encode_UUID_TTLV(TD_TTLV_TAG_OBJECTID, object_id_string.c_str(), object_id_string.length(), shift_length, placeholder);

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Container_Id_TTLV(const TDSC_CONTAINER_ID_t container_id, TDSC_LENGTH_t& shift_length,  char * placeholder) {
        bool return_code = false;
        std::string container_id_string = to_string(container_id);

        return_code = encode_UUID_TTLV(TD_TTLV_TAG_CONTAINERID, container_id_string.c_str(), container_id_string.length(), shift_length, placeholder);

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Container_Type_TTLV(const TDSC_CONTAINER_t container_type, char * placeholder) {
        bool return_code = false;
        TDSC_CONTAINER_t container_type_length = sizeof(TDSC_CONTAINER_t);

        if( encode_Tag_TTLV(TD_TTLV_TAG_CONTAINERTYPE, placeholder) ) {
            placeholder += sizeof(TDSC_TAG_t);

            if( encode_Type_TTLV(TD_TTLV_TYPE_SYMBOL, placeholder) ) {
                placeholder += sizeof(TDSC_TYPE_t);

                if( encode_Length_TTLV(container_type_length, placeholder) ) {
                    placeholder += sizeof(TDSC_CONTAINER_t);

                    if( _encode_uint8_TTLV(container_type, placeholder) ) {
                        return_code = true;
                    }
                }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Key_Type_TTLV(const TDSC_KEY_TYPE_t key_type, char * placeholder) {
        bool return_code = false;
        uint64_t key_type_length = sizeof(uint8_t);

        if( encode_Tag_TTLV(TD_TTLV_TAG_KEYTYPE, placeholder) ) {
            placeholder += sizeof(TDSC_TAG_t);

            if( encode_Type_TTLV(TD_TTLV_TYPE_SYMBOL, placeholder) ) {
                placeholder += sizeof(TDSC_TYPE_t);

                if( encode_Length_TTLV(key_type_length, placeholder) ) {
                    placeholder += sizeof(uint64_t);

                    if( _encode_uint8_TTLV(key_type, placeholder) ) {
                        return_code = true;
                    }
                }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_SizeInBytes_TTLV(const TDSC_SIZE_IN_BYTES_t size_in_bytes, char * placeholder) {
        bool return_code = false;
        uint64_t size_in_bytes_length = sizeof(uint64_t);

        if( encode_Tag_TTLV(TD_TTLV_TAG_SIZEINBYTES, placeholder) ) {
            placeholder += sizeof(TDSC_TAG_t);

            if( encode_Type_TTLV(TD_TTLV_TYPE_INTEGER, placeholder) ) {
                placeholder += sizeof(TDSC_TYPE_t);

               if( encode_Length_TTLV(size_in_bytes_length, placeholder) ) {
                    placeholder += sizeof(uint64_t);

                    if( _encode_uint64_TTLV(size_in_bytes, placeholder) ) {
                        return_code = true;
                    }
               }
            }
        }

        return return_code;
    }

    bool TDS_TTLV_Tools::encode_Command_Type(const TDSC_COMMAND_t command_type, char * placeholder) {
        bool return_code = memcpy(placeholder, reinterpret_cast<void*>(const_cast<uint8_t*>(&command_type)), sizeof(TDSC_COMMAND_t));

        return return_code;
    }

    void TDS_TTLV_Tools::dump_Command(char * msg, uint64_t msg_length) {
        uint64_t msg_offset = 0;
        char * msg_cursor = msg;

        TDSC_TAG_t  msg_tag;
        TDSC_TYPE_t msg_type;
        TDSC_LENGTH_t msg_len;

        uint64_t msg_integer_value;

        // dump command type
        uint8_t cmd_type;
        memcpy(&cmd_type, msg, sizeof(uint8_t));
        ttlv_logger->debug("Command Type: [{0:x}] [{1}]", cmd_type, TDS_TTLV_Tools::CMD_to_string(cmd_type));

        msg_cursor += sizeof(uint8_t);
        msg_offset += sizeof(uint8_t);

        while( msg_offset < msg_length ) {
            memcpy(&msg_tag, msg_cursor, sizeof(TDSC_TAG_t));
            msg_cursor += sizeof(TDSC_TAG_t);
            msg_offset += sizeof(TDSC_TAG_t);

            memcpy(&msg_type, msg_cursor, sizeof(TDSC_TYPE_t));
            msg_cursor += sizeof(TDSC_TYPE_t);
            msg_offset += sizeof(TDSC_TYPE_t);

            memcpy(&msg_len, msg_cursor, sizeof(TDSC_LENGTH_t));
            msg_cursor += sizeof(TDSC_LENGTH_t);
            msg_offset += sizeof(TDSC_LENGTH_t);

            ttlv_logger->debug("\tTAG:    [{0:x}][{0:d}] [{1}]", msg_tag, TDS_TTLV_Tools::TAG_to_string(msg_tag));
            ttlv_logger->debug("\tTYPE:   [{0:x}][{0:d}] [{1}]", msg_type, TDS_TTLV_Tools::TYPE_to_string(msg_type));
            if( msg_type == TD_TTLV_TYPE_INTEGER ) {
                memcpy(&msg_integer_value, msg_cursor, sizeof(uint64_t));
                ttlv_logger->debug("\tLENGTH: [{}]\tVALUE: [{}]", msg_len, msg_integer_value);
            } else {
                ttlv_logger->debug("\tLENGTH: [{}]", msg_len);
            }
            ttlv_logger->debug("-----------------------------------");

            msg_cursor += msg_len;
            msg_offset += msg_len;
        }
    }

    uuid TDS_TTLV_Tools::get_id_from_bytestring(const bytestring& bytestring) {
        std::string id_string = std::string(bytestring.data,bytestring.length);
        boost::uuids::uuid id;
        try {
            id = boost::lexical_cast<uuid>(id_string);
        } catch( boost::bad_lexical_cast & ) {}

        return id;
    }

    uuid TDS_TTLV_Tools::get_id_from_string(const std::string& uuid_string) {
        boost::uuids::uuid id;
        try {
            id = boost::lexical_cast<uuid>(uuid_string);
        } catch( boost::bad_lexical_cast & ) {}

        return id;
    } 

    std::string TDS_TTLV_Tools::TYPE_to_string(const TDSC_TYPE_t  msg_type) {
        std::string type_string = "UNKNOWN";
        switch( msg_type ) {
            case 1 :    type_string = "SYMBOL";
                        break;
            case 2 :    type_string = "BYTESTRING";
                        break;
            case 3 :    type_string = "UNICODESTRING";
                        break;
            case 4 :    type_string = "INTEGER";
                        break;
            case 5 :    type_string = "SHORTINTEGER";
                        break;
            case 6 :    type_string = "PAIR";
                        break;
            case 7 :    type_string = "UUID";
                        break;
        }

        return type_string;
    }

    std::string TDS_TTLV_Tools::TAG_to_string(const TDSC_TAG_t  msg_tag) {
        std::string tag_string = "UNKNOWN";
        switch( msg_tag ) {
            case  1 :   tag_string = "CONTAINERTYPE";
                        break;
            case  2 :   tag_string = "LTDID";
                        break;
            case  4 :   tag_string = "LTDROLE";
                        break;
            case  5 :   tag_string = "CN";
                        break;
            case  6 :   tag_string = "OBJECTID";
                        break;
            case  7 :   tag_string = "SESSIONID";
                        break;
            case  8 :   tag_string = "CONTAINERID";
                        break;
            case  9 :   tag_string = "CONTAINERNAME";
                        break;
            case 10 :   tag_string = "SIGNEDDATA";
                        break;
            case 11 :   tag_string = "DBKEYVALUE";
                        break;
            case 12 :   tag_string = "DBKEY";
                        break;
            case 13 :   tag_string = "DBVALUE";
                        break;
            case 14 :   tag_string = "STATUSCODE";
                        break;
            case 15 :   tag_string = "PERMANENTFILE";
                        break;
            case 16 :   tag_string = "PERMANENTDATABASE";
                        break;
            case 17 :   tag_string = "FILE";
                        break;
            case 18 :   tag_string = "DATABASE";
                        break;
            case 22 :   tag_string = "EVENT";
                        break;
            case 23 :   tag_string = "SUBJECT";
                        break;
            case 24 :   tag_string = "CONTEXT";
                        break;
            case 25 :   tag_string = "SIZEINBYTES";
                        break;
            case 26 :   tag_string = "DATA";
                        break;
            case 27 :   tag_string = "NONCE";
                        break;
            case 29 :   tag_string = "KEYTYPE";
                        break;
            case 30 :   tag_string = "RSAKEY1024";
                        break;
            case 31 :   tag_string = "RSAKEY2048";
                        break;
            case 32 :   tag_string = "RSAKEY4096";
                        break;
            case 33 :   tag_string = "SYMMETRICKEY128";
                        break;
            case 34 :   tag_string = "SYMMETRICKEY256";
                        break;
        }

        return tag_string;
    }

    std::string TDS_TTLV_Tools::CMD_to_string(const uint8_t cmd_type) {
        std::string cmd_string = "UNKNOWN";
        switch( cmd_type ) {
            case 110 :  cmd_string = "TD_CREATEOBJECT_CMD";
                        break;
            case 100 :  cmd_string = "TD_GETOBJECTVALUE_CMD";
                        break;
            case   2 :  cmd_string = "TD_OPENCONNECTION_CMD";
                        break;
            case   4 :  cmd_string = "TD_PUTOBJECTVALUE_CMD";
                        break;
            case   6 :  cmd_string = "TD_CREATESESSION_CMD";
                        break;
            case   8 :  cmd_string = "TD_CLOSESESSION_CMD";
                        break;
            case  10 :  cmd_string = "TD_GETRANDOM_CMD";
                        break;
            case  12 :  cmd_string = "TD_GENERATEENCRYPTIONKEY_CMD";
                        break;
            case  14 :  cmd_string = "TD_CREATEARCHIVE_CMD";
                        break;
            case  16 :  cmd_string = "TD_ARCHIVE_CMD";
                        break;
            case  18 :  cmd_string = "TD_CLOSEARCHIVE_CMD";
                        break;
            case  20 :  cmd_string = "TD_CREATESTORAGE_CMD";
                        break;
            case  22 :  cmd_string = "TD_DELETESTORAGE_CMD";
                        break;
            case  24 :  cmd_string = "TD_STOREDATA_CMD";
                        break;
            case  26 :  cmd_string = "TD_GETVALUE_CMD";
                        break;
            case  28 :  cmd_string = "TD_GETSTORAGEVALUE_CMD";
                        break;
            case  30 :  cmd_string = "TD_GETSTORAGE_CMD";
                        break;
            case  32 :  cmd_string = "TD_SEARCH_CMD";
                        break;
            case  34 :  cmd_string = "TD_GETTRUSTEDTIMESTAMP_CMD";
                        break;
            case  36 :  cmd_string = "TD_TRUSTRENEWAL_CMD";
                        break;
        }
        
        return cmd_string;
    }

}
