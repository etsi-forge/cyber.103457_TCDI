#ifndef TDS_CONNECTION_COMMANDS_H
#define TDS_CONNECTION_COMMANDS_H

/*!
* \file TDS_Connection_Commands.h
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Commands.h"
#include "TDS_Session_Manager.h"

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_OpenConnection_Command
    * 
    *  This class is intended manage the Open Connection 
    */

    class TD_OpenConnection_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_OpenConnection_Command();

            /*!
             *  Destructor
             */
            ~TD_OpenConnection_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_ROLE
             * - TDSC_TRUST_REFUSED
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t execute_command() override;            

            /*!
             *  Retrieve the coonfigurtion container id associated to the Connection 
             *  \param[out] container_id
             */
            void get_container_id(TDSC_CONTAINER_ID_t& container_id) { container_id = _config_container_id; };

        private:

            /*!
             *  Parse the TD_Message following the TTLV convention
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t _parse_command_message() override;

            TDSC_CONTAINER_ID_t _config_container_id;       /*!< Data*/
    };

    /*! \class TD_CloseConnection_Command
    * 
    *  This class is intended manage the Close Connection 
    */

    class TD_CloseConnection_Command final : public TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_CloseConnection_Command();

            /*!
             *  Destructor
             */
            ~TD_CloseConnection_Command() override;

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             * - TDSC_SUCCESS
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t execute_command() override;

    };
}

#endif
