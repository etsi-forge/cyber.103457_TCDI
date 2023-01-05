#ifndef TDSC_ARCHIVE_COMMANDS_H
#define TDSC_ARCHIVE_COMMANDS_H

/*!
* \file TDS_Archive_Commands.h
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457 MTD interfaces
*/

#include "TDS_CType.h"
#include "TDS_Commands.h"

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_CreateArchive_Command
    *
    *  This class is intended to Create an archive in the MTD\n
    *  The Archive's lifecycle is within its creation Session\n
    *  The newly created Archive is identified by its container_id\n
    *  Archive is a write only container
    */

    class TD_CreateArchive_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_CreateArchive_Command();

            /*!
             *  Destructor
             */
            ~TD_CreateArchive_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_STORAGE_FULL
             * - TDSC_CONTAINER_TYPE_NOT_SUPPORTED
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE
             * - TDSC_OBJECT_CREATION_FAILED 
             * - TDSC_CONTAINER_CREATION_FAILED
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  Retrieve the container_id identifier of the Archive
             *  \param[out] container_id
             */
            void get_container_id(TDSC_CONTAINER_ID_t& container_id) { container_id = _td_object_id; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_CONTAINER_t    _td_container_type;     /*!< the container type*/
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the archive/object id*/
    };  

    /*! \class TD_CloseArchive_Command
    *
    *  This class is intended to Close an Archive previously created in the MTD (in the same Session)\n
    *  The Archive is identified by its container_id
    */

    class TD_CloseArchive_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_CloseArchive_Command();

            /*!
             *  Destructor
             */
            ~TD_CloseArchive_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t
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
            
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the archive/object id*/
    };

    /*! \class TD_Archive_Command
    *
    *  This class is intended to Add data to an Archive previously created int the MTD\n
    *  The Archive is identified by its container_id
    */

    class TD_Archive_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
            TD_Archive_Command();

            /*!
             *  Destructor
             */
            ~TD_Archive_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_DATA_TYPE_NOT_SUPPORTED
             * - TDSC_UNKNOWN_CONTAINER_ID
             * - TDSC_STORAGE_FULL
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE   
             * - TDSC_OBJECT_CREATION_FAILED          
             */
            TDSC_STATUS_CODE_t execute_command() override;

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;
            
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the archive/object id*/
            TDSC_DATA_t         _td_data;               /*!< the container data*/
    };
}

#endif
