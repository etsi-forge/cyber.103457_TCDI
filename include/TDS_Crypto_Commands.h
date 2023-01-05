#ifndef TDS_CRYPTO_COMMANDS_H
#define TDS_CRYPTO_COMMANDS_H

/*!
* \file TDS_Crypto_Commands.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Commands.h"

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_GenerateEncryptionKey_Command
    * 
    *  This class is intended to manage the Encryption Key Generation on the MTD
    */

    class TD_GenerateEncryptionKey_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_GenerateEncryptionKey_Command();

            /*!
             *  Destructor
             */
            ~TD_GenerateEncryptionKey_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_KEY_TYPE
             * - TDSC_KEY_SIZE_NOT_SUPPORTED
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE  
             * - TDSC_OBJECT_CREATION_FAILED           
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_object_id
             *  \param[out] object_id
             */
            void get_object_id(TDSC_OBJECT_ID_t& object_id) { object_id = _td_object_id; };
            
        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the object_id*/
            TDSC_KEY_TYPE_t     _td_key_type;           /*!< Data*/
            TDSC_PASSPHRASE_t   _td_passphrase;         /*!< Data*/
    };

    /*! \class TD_GetRandom_Command
    * 
    *  This class is intended to manage the Random Generation on the MTD
    */

    class TD_GetRandom_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_GetRandom_Command();

            /*!
             *  Destructor
             */
            ~TD_GetRandom_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE
             * - TDSC_OBJECT_CREATION_FAILED             
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_object_id
             *  \param[out] object_id
             */
            void get_object_id(TDSC_OBJECT_ID_t& object_id) { object_id = _td_object_id; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_OBJECT_ID_t        _td_object_id;            /*!< the object_id*/
            TDSC_SIZE_IN_BYTES_t    _td_sizeinbytes;          /*!< the random size if byte*/
    };

    /*! \class TD_GetTrustedTimeStamping_Command
    * 
    *  This class is intended to manage the Trusted Time Stamp Generation on the MTD
    */

    class TD_GetTrustedTimeStamping_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_GetTrustedTimeStamping_Command();

            /*!
             *  Destructor
             */
            ~TD_GetTrustedTimeStamping_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE   
             * - TDSC_OBJECT_CREATION_FAILED          
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_object_id
             *  \param[out] object_id
             */
            void get_object_id(TDSC_OBJECT_ID_t& object_id) { object_id = _td_object_id; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_OBJECT_ID_t    _td_object_id;           /*!< the object_id*/
            TDSC_DATA_t         _td_data;                /*!< the object data*/
    };

    /*! \class TD_TrustRenewal_Command
    * 
    *  This class is intended to manage the Trust Link between LTD and MTD
    */

    class TD_TrustRenewal_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_TrustRenewal_Command();

            /*!
             *  Destructor
             */
            ~TD_TrustRenewal_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_ATTESTATION_FAILED
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t execute_command() override;

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;
            TDSC_CERT_COMMON_NAME_t _td_certificate_CN;       /*!< e certificate common name */
            TDSC_NONCE_t            _td_nonce;                /*!< Nonce value*/
            TDSC_DATA_t             _td_data;                 /*!< the object data*/
    };
}

#endif
