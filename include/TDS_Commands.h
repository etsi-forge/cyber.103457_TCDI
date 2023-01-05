#ifndef TDSC_COMMANDS_H
#define TDSC_COMMANDS_H

/*!
* \file TDS_Commands.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Constants.h"
#include <cstring>

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_Message
    * 
    *  This class represents the binary data exchanged between the the LTD and the MTD
    *  the message_stream is duplicated, therefore released by its destructor
    */

    class TD_Message {
        public:

            /*!
             *  Constructor
             *  \param[in] message_stream The message_stream is duplicated 
             *  \param[in] message_length The message length
             */
            TD_Message(char *, uint64_t);

            /*!
             *  Destructor
             */
            ~TD_Message();

            /*!
             *  Retrieve the message_stream component
             *  \return The message_stream pointer (can be nullptr)
             */
            char * get_message_stream() { return _message_stream; };
            
            /*!
             *  Retrieve the message_stream length
             *  \return message_stream: The message stream length
             */            
            uint64_t get_length() {return _message_length; };

        private:

            //TDSC_MESSAGE_ID_t   _message_id;                  /*!< Fure use when dealing with Asynchronous Commands*/
            char *              _message_stream = nullptr;      /*!< the message length*/
            uint64_t            _message_length = UINT64_C(0);  /*!< the message content*/
    };

    /*! \class TD_Command
    * 
    *  This is the Base Class of all Commands
    * 
    */

    class TD_Command {
        public:

            /*!
             *  Constructor
             */
            TD_Command();

            /*!
             *  Constructor
             *  \param[in] session_id The session id 
             */
            TD_Command(TDSC_SESSION_ID_t);

            /*!
             *  Destructor
             */
            virtual ~TD_Command();

            /*!
             *  Set the command type
             *  \param[in] cmd_type The command type
             */

            void set_command_type(TDSC_COMMAND_t cmd_type) { _command_type = cmd_type; };

            /*!
             *  Associate the TD_Message to the command
             *  \param[in] msg The TD_Message associated to the Command
             */

            void set_message(TD_Message *);

            /*!
             *  Execute the command after parsing and validating the requiered arguments in the associated TD_Message
             *  \return TDSC_STATUS_CODE_t The Status of execution
             */
            virtual TDSC_STATUS_CODE_t execute_command()       = 0;

            /*!
             *  Retrieve the response_id corresponding to the command reponse
             *  (not used)
             *  \return TDSC_MESSAGE_ID_t The response id/type
             */
            TDSC_MESSAGE_ID_t get_response_id() { return _response_id; };

        protected:

            /*!
             *  Parse the TD_Message following the TTLV convention
             *  \return TDSC_STATUS_CODE_t
             */
            virtual TDSC_STATUS_CODE_t _parse_command_message() { return TDSC_SUCCESS; };

            TDSC_COMMAND_t      _command_type = UINT8_C(0);     /*!< the command type*/
            TDSC_SESSION_ID_t   _session_id;                    /*!< the session id associated to the command*/
            TD_Message        * _message = nullptr;             /*!< the TD_Message associated to the command*/
            TDSC_STATUS_CODE_t  _status_code  = TDSC_SUCCESS;    /*!< the status code returned after completion*/
            TDSC_MESSAGE_ID_t   _response_id;                   /*!< the response id*/
    };
}

#endif
