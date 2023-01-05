#ifndef TDS_SESSIONS_MANAGER_H
#define TDS_SESSIONS_MANAGER_H

/*!
* \file TDS_Session_Manager.h
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Constants.h"
#include "TDS_Object.h"
#include "TDS_Session.h"

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_Session_Manager
    *
    *  This class is intended to manage sessions lifecycle within a connection
    *  creation, deletion, session retieval
    */

    class TD_Session_Manager {

        public:

            /*!
             *  Constructor
             */
            TD_Session_Manager();

            /*!
             *  Destructor
             */
            ~TD_Session_Manager();

            /*!
             *  Add a session to manage to the session manager 
             *  Sessions are added to the session manager as a tuple (session id, session ptr)
             *  \param[in] session_id The session id to add
             *  \param[in] session_ptr The session pointer 
             *  \return bool
             * - True if session correctly added
             * - False otherwise
             */
            bool add_session(TDSC_SESSION_ID_t, TD_Session *);

            /*!
             *  Remove a session from the session manager
             *  \param[in] session_id The session id
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_SESSION_ID
             */
            
            TDSC_STATUS_CODE_t remove_session(TDSC_SESSION_ID_t);

            /*!
             *  Remove all sessions from the session manager
             */
            void clear_sessions();

            /*!
             *  Retrieve the session ptr from its session id
             *  \param[in] session_id The session id searched for
             *  \return TD_Session * or nullptr
             */
            TD_Session * get_session_by_id(TDSC_SESSION_ID_t&);

            /*!
             *  Check if a session can be added to the session manager
             *  Used if managed sessions are limited on the MTD
             *  \return bool
             * - True if a session can be added
             * - False otherwise
             */
            bool can_add_new_session();

            /*!
             *  dump registered sessions
             */
             void detailed_dump();

        private:

            TDSC_SESSION_MAP_t        * _session_map = nullptr;     /*!< The session map<session_id, session_ptr> */
            uint64_t                    _max_session = UINT64_C(0); /*!< The maximum session allowed on the MTD. 0=unlimited*/
    };
}

#endif
