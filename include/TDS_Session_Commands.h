#ifndef TDS_SESSION_COMMANDS_H
#define TDS_SESSION_COMMANDS_H

/*!
* \file TDS_Session_Commands.h
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Constants.h"
#include "TDS_Commands.h"

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_CreateSession_Command
    * ...
    *
    *  ...
    */

    class TD_CreateSession_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_CreateSession_Command();

            /*!
             *  Destructor
             */
            ~TD_CreateSession_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_SESSION_ID_ALREADY_OPENED
             * - TDSC_TOO_MANY_EXISTING_SESSIONS
             * - TDSC_TRUST_EXPIRED
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t execute_command() override;

            /*!
             *  get_session_id
             *  \return TDSC_SESSION_ID_t
             */
            TDSC_SESSION_ID_t get_session_id() { return _session_id; };

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override { return TDSC_SUCCESS; };
    };

    /*! \class TD_CloseSession_Command
    * ...
    *
    *  ...
    */

    class TD_CloseSession_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_CloseSession_Command();

            /*!
             *  Destructor
             */
            ~TD_CloseSession_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             * - TDSC_ON_GOING_PROCESSES
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t execute_command() override;

        private:

            /*!
             *  parse_command_message
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;
    };
}

#endif
