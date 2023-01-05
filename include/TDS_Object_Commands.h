#ifndef TDSC_OBJECT_COMMANDS_H
#define TDSC_OBJECT_COMMANDS_H

/*!
* \file TDS_Object_Commands.h
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

    /*! \class TD_CreateObject_Command
    * 
    *  This class is intended to manage the Object Creation Command
    */

    class TD_CreateObject_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_CreateObject_Command();

            /*!
             *  Destructor
             */
            ~TD_CreateObject_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_TRUST_EXPIRED
             * - TDSC_OBJECT_CREATION_FAILED
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  Retrieve the Object Id created
             *  \param[out] object_id the Object object_id created
             */
            void get_object_id(TDSC_OBJECT_ID_t& object_id) { object_id = _td_object_id; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the object_id*/
    };

    /*! \class TD_GetObjectValue_Command
    * 
    *  This class is intended to manage the Object Value Retrieve Command
    */

    class TD_GetObjectValue_Command final : public TD_Command  {
        public:

            /*!
             *  Constructor
             */
             TD_GetObjectValue_Command();

            /*!
             *  Destructor
             */
            ~TD_GetObjectValue_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_OBJECT_ID
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE             
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  Retrieve the Object Value coresponding to the object_id 
             *  \param[out] object_value The object data value
             */
            void get_object_value(TDSC_DATA_t& object_value) { object_value.length = _td_data.length; object_value.data = _td_data.data; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the object_id*/
            TDSC_DATA_t         _td_data;               /*!< the object data*/
    };

    /*! \class TD_PutObjectValue_Command
    * 
    *  This class is intended to manage the Object Value Setting Command
    */

    class TD_PutObjectValue_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_PutObjectValue_Command();

            /*!
             *  Destructor
             */
            ~TD_PutObjectValue_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_UNKNOWN_OBJECT_ID
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
            TDSC_OBJECT_ID_t    _td_object_id;          /*!< the object_id*/
            TDSC_DATA_t         _td_data;               /*!< the object data*/
    };
}

#endif
