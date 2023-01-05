#ifndef TDSC_STORAGE_COMMANDS_H
#define TDSC_STORAGE_COMMANDS_H

/*!
* \file TDS_Storage_Commands.h
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

    /*! \class TD_CreateStorage_Command
    * ...
    *
    *  ...
    */

    class TD_CreateStorage_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_CreateStorage_Command();

            /*!
             *  Destructor
             */
            ~TD_CreateStorage_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_CONTAINER_TYPE_NOT_SUPPORTED
             * - TDSC_STORAGE_FULL
             * - TDSC_TRUST_EXPIRED
             * - TDSC_CONTAINER_NAME_ALREADY_EXISTS
             * - TDSC_GENERAL_FAILURE 
             * - TDSC_OBJECT_CREATION_FAILED   
             * - TDSC_CONTAINER_CREATION_FAILED        
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_container_id
             *  \param[out] container_id
             */
            void get_container_id(TDSC_CONTAINER_ID_t& container_id) { container_id = _td_container_id; };

        private:
            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            std::string             _td_container_name;     /*!< Data*/
            TDSC_CONTAINER_t        _td_container_type;     /*!< Data*/
            TDSC_CONTAINER_ID_t     _td_container_id;       /*!< Data*/
    };

    /*! \class TD_DeleteStorage_Command
    * ...
    *
    *  ...
    */

    class TD_DeleteStorage_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_DeleteStorage_Command();

            /*!
             *  Destructor
             */
            ~TD_DeleteStorage_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_CONTAINER_ID
             * - TDSC_STORAGE_BUSY
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

            TDSC_CONTAINER_ID_t _td_container_id;       /*!< Data*/
    };

    /*! \class TD_StoreData_Command
    * ...
    *
    *  ...
    */

    class TD_StoreData_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_StoreData_Command();

            /*!
             *  Destructor
             */
            ~TD_StoreData_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_CONTAINER_ID
             * - TDSC_DATA_TYPE_NOT_SUPPORTED
             * - TDSC_STORAGE_FULL
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
            TDSC_CONTAINER_ID_t _td_container_id;       /*!< the container id*/
            TDSC_DATA_t         _td_data;               /*!< the object data*/
    };

    /*! \class TD_GetValue_Command
    * ...
    *
    *  ...
    */

    class TD_GetValue_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_GetValue_Command();

            /*!
             *  Destructor
             */
            ~TD_GetValue_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             */
            TDSC_STATUS_CODE_t execute_command() override;

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;
    };

    /*! \class TD_GetStorageValue_Command
    * ...
    *
    *  ...
    */

    class TD_GetStorageValue_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_GetStorageValue_Command();

            /*!
             *  Destructor
             */
            ~TD_GetStorageValue_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_CONTAINER_ID
             * - TDSC_CONTAINER_TYPE_NOT_SUPPORTED
             * - TDSC_UNKNOWN_KEY
             * - TDSC_CONTAINER_WRITE_ONLY
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE             
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_data
             *  \param[out] data
             */
            void get_data(TDSC_DATA_t& data) { data.length = _td_data.length; data.data = _td_data.data; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_CONTAINER_ID_t _td_container_id;       /*!< the container id*/
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the object_id*/
            TDSC_DATA_t         _td_data;               /*!< the object data*/
    };

    /*! \class TD_GetStorage_Command
    * ...
    *
    *  ...
    */

    class TD_GetStorage_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_GetStorage_Command();

            /*!
             *  Destructor
             */

            ~TD_GetStorage_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_CONTAINER_WRITE_ONLY
             * - TDSC_CONTAINER_NAME_NOT_FOUND
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE             
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_container_id
             *  \param[out] container_id
             */
            void get_container_id(TDSC_CONTAINER_ID_t& container_id) { container_id = _td_container_id; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_CONTAINER_ID_t _td_container_id;       /*!< the container data*/
            std::string         _td_container_name;     /*!< the container name*/
    };

    /*! \class TD_Search_Command
    * ...
    *
    *  ...
    */

    class TD_Search_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_Search_Command();

            /*!
             *  Destructor
             */
            ~TD_Search_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_CONTAINER_ID
             * - TDSC_VALUE_NOT_FOUND
             * - TDSC_CONTAINER_WRITE_ONLY
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE             
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
            
            TDSC_CONTAINER_ID_t _td_container_id;       /*!< the container id*/
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the object_id*/
            TDSC_DATA_t         _td_data;
    };
}

#endif
