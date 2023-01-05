#include <chrono>

#include "TDS_Constants.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_Crypto_Commands.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <boost/uuid/uuid_io.hpp>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/system_rng.h>

#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/cipher_mode.h>
#include <botan/block_cipher.h>

namespace TDS {

    auto crypt_logger = spdlog::stdout_color_mt("crypto");  /*!< Cryptographic Commands related spdlog Logger */

    /* GenerateEncryptionKey_Command */

    TD_GenerateEncryptionKey_Command::TD_GenerateEncryptionKey_Command() {
        _response_id = TD_GENERATEENCRYPTIONKEY_RSP;
    }

    TD_GenerateEncryptionKey_Command::~TD_GenerateEncryptionKey_Command() {
    }

    TDSC_STATUS_CODE_t TD_GenerateEncryptionKey_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Key_Type(stream_ptr, shift_length, _td_key_type) ) {

                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_GenerateEncryptionKey_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS ) {
            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);

            if( session ) {
                std::unique_ptr<Botan::RandomNumberGenerator> rng;
                Botan::RSA_PrivateKey * prv_key;

                std::string pub_key;
                std::string priv_key;
                std::string keys_str;

                std::unique_ptr<Botan::Cipher_Mode> cipher;
                size_t min_length = 0;

#if defined(BOTAN_HAS_SYSTEM_RNG)
                rng.reset(new Botan::System_RNG);
#else
                rng.reset(new Botan::AutoSeeded_RNG);
#endif
                switch( _td_key_type ) {

                    /* Asymetric encryption : generating key pair */
                    case TD_TTLV_TAG_RSAKEY1024:
                        {
                            prv_key = new Botan::RSA_PrivateKey(*rng,1024);
                            pub_key = Botan::X509::PEM_encode(*prv_key);
                            priv_key = Botan::PKCS8::PEM_encode(*prv_key);
                            keys_str = pub_key + "\n" + priv_key;
                        }
                        break;
                    case TD_TTLV_TAG_RSAKEY2048:
                        {
                            prv_key = new Botan::RSA_PrivateKey(*rng,2048);
                            pub_key = Botan::X509::PEM_encode(*prv_key);
                            priv_key = Botan::PKCS8::PEM_encode(*prv_key);
                            keys_str = pub_key + "\n" + priv_key;
                        }
                        break;
                    case TD_TTLV_TAG_RSAKEY4096:    
                        {
                            prv_key = new Botan::RSA_PrivateKey(*rng,4096);
                            pub_key = Botan::X509::PEM_encode(*prv_key);
                            priv_key = Botan::PKCS8::PEM_encode(*prv_key);
                            keys_str = pub_key + "\n" + priv_key;
                        }
                        break;

                    /* Symmetric encryption : generating single key */
                    case TD_TTLV_TAG_SYMMETRICKEY128: // AES-128
                        {
                            cipher = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION);
                            min_length = cipher->minimum_keylength();
                            Botan::secure_vector<uint8_t> result(min_length);
                            rng->randomize(result.data(), result.size());

                            char rbuffer[4];

                            for( uint8_t itv : result ) {
                                sprintf(rbuffer, "%02X", itv);
                                keys_str.append(rbuffer);
                            }
                        }
                        break;
                    case TD_TTLV_TAG_SYMMETRICKEY256: // AES-256
                        { 
                            cipher = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::ENCRYPTION);
                            min_length = cipher->minimum_keylength();
                            Botan::secure_vector<uint8_t> result(min_length);
                            rng->randomize(result.data(), result.size());

                            char rbuffer[4];

                            for( uint8_t itv : result ) {
                                sprintf(rbuffer, "%02X", itv);
                                keys_str.append(rbuffer);
                            }
                        }
                        break;
                    default:
                        {
                            keys_str = "N/A";
                            crypt_logger->debug("default");
                            return_code = TDSC_KEY_SIZE_NOT_SUPPORTED;
                        }
                        break;
                }

                crypt_logger->info("\n{}", keys_str);
                TD_Object * object = new TD_Object(keys_str.c_str(), keys_str.length());
                _td_object_id = session->add_object(object);

                if( _td_object_id.is_nil() ) return_code = TDSC_OBJECT_CREATION_FAILED;

            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

    TD_GetRandom_Command::TD_GetRandom_Command() {
        _response_id = TD_GETRANDOM_RSP;
    }

    TD_GetRandom_Command::~TD_GetRandom_Command() {
    }

    TDSC_STATUS_CODE_t TD_GetRandom_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;

            if( TDS_TTLV_Tools::decode_TTLV_SizeInBytes(stream_ptr, shift_length, _td_sizeinbytes) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_GetRandom_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS ) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);

            if( session ) {

                std::unique_ptr<Botan::RandomNumberGenerator> rng;

#if defined(BOTAN_HAS_SYSTEM_RNG)
                rng.reset(new Botan::System_RNG);
#else
                rng.reset(new Botan::AutoSeeded_RNG);
#endif
                size_t vector_size = (size_t)_td_sizeinbytes;
                Botan::secure_vector<uint8_t> result(vector_size);
                rng->randomize(result.data(), result.size());
                
                char rbuffer[4];
                std::string random_string("");

                for( uint8_t itv : result ) {
                    sprintf(rbuffer, "%02X", itv);
                    random_string.append(rbuffer);
                }
                crypt_logger->debug("Random: {:Xn}", spdlog::to_hex(std::begin(result), std::begin(result) + vector_size));
                TD_Object * object = new TD_Object(random_string.c_str(), random_string.length());
                _td_object_id = session->add_object(object);
                if( _td_object_id.is_nil() ) return_code = TDSC_OBJECT_CREATION_FAILED;

            } else return_code = TDSC_UNKNOWN_SESSION_ID;

        }

        return return_code;
    }

    TD_GetTrustedTimeStamping_Command::TD_GetTrustedTimeStamping_Command() {
        _response_id = TD_GETTRUSTEDTIMESTAMP_RSP;
    }

    TD_GetTrustedTimeStamping_Command::~TD_GetTrustedTimeStamping_Command() {
        if( _td_data.data ) delete [] _td_data.data;
    }

    TDSC_STATUS_CODE_t TD_GetTrustedTimeStamping_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        char * stream_ptr = _message->get_message_stream() + sizeof(TDSC_COMMAND_t);

        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_data) ) {
                return_code = TDSC_SUCCESS;
            }
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_GetTrustedTimeStamping_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();

        if( return_code == TDSC_SUCCESS ) {

            TD_Session * session = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(_session_id);
            if( session ) {
                // Generate Trusted Time Stamp
                int64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                crypt_logger->debug("Generated Trusted Timestamp: {}", timestamp);
                TD_Object * object = new TD_Object(reinterpret_cast<char *>(&timestamp), sizeof(int64_t));
                _td_object_id = session->add_object(object);
                if( _td_object_id.is_nil() ) return_code = TDSC_OBJECT_CREATION_FAILED;

            } else return_code = TDSC_UNKNOWN_SESSION_ID;
        }

        return return_code;
    }

    TD_TrustRenewal_Command::TD_TrustRenewal_Command() {
        _response_id = TD_TRUSTRENEWAL_RSP;
    }

    TD_TrustRenewal_Command::~TD_TrustRenewal_Command() {
        // Cleanup allocations
        if( _td_nonce.data ) delete [] _td_nonce.data;
        if( _td_data.data )  delete [] _td_data.data;
    }

    TDSC_STATUS_CODE_t TD_TrustRenewal_Command::_parse_command_message() {
        if( !_message ) return TDSC_GENERAL_FAILURE;

        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        uint64_t shift_length;

        // Skipping COMMAND type (uint8_t)
        char * stream_ptr = _message->get_message_stream() + sizeof(uint8_t);

        // Retrieving Session-If LTD-Role, CN, Nonce and DATA
        if( TDS_TTLV_Tools::decode_TTLV_Session_Id(stream_ptr, shift_length, _session_id) ) {
            stream_ptr += shift_length;
            if( TDS_TTLV_Tools::decode_TTLV_Unicode_String(stream_ptr, TD_TTLV_TAG_CN, TD_TTLV_TYPE_UNICODESTRING, shift_length, _td_certificate_CN) ) {
                stream_ptr += shift_length;
                if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_NONCE, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_nonce) ) {
                    stream_ptr += shift_length;
                    if( TDS_TTLV_Tools::decode_TTLV_Byte_String(stream_ptr, TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, shift_length, _td_data) ) {
                        return_code = TDSC_SUCCESS;
                    }
                }
            }
        }

        return return_code;
    }


    TDSC_STATUS_CODE_t TD_TrustRenewal_Command::execute_command() {
        TDSC_STATUS_CODE_t return_code = _parse_command_message();
        return_code = TDS::TD_Connection::get_connection()->check_connection_trust(_td_certificate_CN, _td_nonce, _td_data);
        
        return return_code;
    }

}

