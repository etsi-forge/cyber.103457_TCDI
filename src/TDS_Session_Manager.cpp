#include <iostream>

#include "TDS_Session.h"
#include "TDS_Connection.h"
#include "TDS_Session_Manager.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <boost/uuid/uuid_io.hpp>

using namespace std;

namespace TDS {

    auto sesmng_logger = spdlog::stdout_color_mt("ses_mngr");   /*!< Session Manager related spdlog Logger */

    /* TD_SessionManager */

    TD_Session_Manager::TD_Session_Manager() {
        _session_map = new map<TDSC_SESSION_ID_t, TD_Session *>();
        sesmng_logger->info("Session Manager created....");
    }

    TD_Session_Manager::~TD_Session_Manager() {
        clear_sessions();
        delete _session_map;
        _session_map = nullptr;
    }

    TD_Session * TD_Session_Manager::get_session_by_id(TDSC_SESSION_ID_t &session_id) {
        TDSC_SESSION_MAP_t::iterator _session_map_it = _session_map->find(session_id);

        if( _session_map_it != _session_map->end() ) return _session_map_it->second;
        else return nullptr;
    }

    bool TD_Session_Manager::add_session(TDSC_SESSION_ID_t session_id, TD_Session * session_ptr) {
        map<TDSC_SESSION_ID_t, TD_Session *>::iterator _session_map_it;
        _session_map->insert(make_pair(session_id, session_ptr));

        return ( _session_map_it != _session_map->end() );
    }

    TDSC_STATUS_CODE_t TD_Session_Manager::remove_session(TDSC_SESSION_ID_t session_id) {
        TDSC_STATUS_CODE_t return_code = TDSC_UNKNOWN_SESSION_ID;
        /* Find session ptr from session id */
        size_t nb_elements = 0;
        sesmng_logger->debug("Session Manager removed session: {} {}", to_string(session_id), nb_elements);
        TDSC_SESSION_MAP_t::iterator _session_map_it = _session_map->find(session_id);
        if( _session_map_it != _session_map->end() ) {
            delete _session_map_it->second;
            /* Remove reference to the session ptr from the session manager map */
            nb_elements = _session_map->erase(session_id);
            return_code = TDSC_SUCCESS;
        }

        return return_code;
    }

    void TD_Session_Manager::clear_sessions() {
        for( auto const& it : (*_session_map) ) {
            delete it.second;
        }
        _session_map->clear();
    }

    bool TD_Session_Manager::can_add_new_session() {
        bool return_code = false;
        if( _max_session == UINT64_C(0) ) {
            return_code = true;
        } else {
            // Check if we have other slots for new sessions
        }
        
        return return_code;
    }

    void TD_Session_Manager::detailed_dump() {
        for( auto const& it : (*_session_map) ) {
            sesmng_logger->info("Registered session: {}", to_string(it.first));
            (it.second)->dump_session();
        }
    }

}
