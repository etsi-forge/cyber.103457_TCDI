#include "TDS_TTLV_Tools.h"
#include "TDS_Session.h"
#include "TDS_Constants.h"
#include "TDS_Container.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

namespace TDS {

    auto sess_logger = spdlog::stdout_color_mt("session");  /*!< Session related spdlog Logger */

    /* TD_Session */

    TD_Session::TD_Session() {
        _session_data = new TDSC_SESSION_DATA_t();
        _session_id = TDS_TTLV_Tools::gen_uuid();
    }

    TD_Session::~TD_Session() {
        for( auto const& it : (*_session_data) )
            delete it.second;
        _session_data->clear();
        delete _session_data;
    }

    uuid TD_Session::get_new_object_id() { 
        return TDS_TTLV_Tools::gen_uuid();
    }

    TDSC_OBJECT_ID_t TD_Session::add_object(TD_Object * object) {
        TDSC_OBJECT_ID_t object_uuid = TDS_TTLV_Tools::gen_uuid();

        auto return_insert = _session_data->insert(make_pair(object_uuid, object));
        if( return_insert.second == false ) object_uuid = nil_uuid();

        return object_uuid;
    }

    void TD_Session::dump_session() {
        std::string tabs("\t\t");
        for( auto const& it : (*_session_data) ) {
            if( (it.second)->is_root_object() ) {
                sess_logger->info("\tObject registered: {}", to_string(it.first));
                (it.second)->dump(tabs);
            } else {
                sess_logger->info("\tContainer registered: {}", to_string(it.first));
                reinterpret_cast<TD_Container*>(it.second)->dump(tabs);
            }
        }
    }

    TDSC_STATUS_CODE_t TD_Session::set_object_value(const TDSC_OBJECT_ID_t object_id, const TDSC_DATA_t& data) {
        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;

        auto const it = _session_data->find(object_id);
        if( it != _session_data->end() ) {
            (it->second)->set_data(data.data, data.length);
            return_code = TDSC_SUCCESS;
        } else {
            sess_logger->error("TD_Session::set_object_value unknown object_id: {}", to_string(object_id));
            return_code = TDSC_UNKNOWN_OBJECT_ID;
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_Session::get_object_value(const TDSC_OBJECT_ID_t object_id, TDSC_DATA_t& data) {
        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;

        auto const it = _session_data->find(object_id);
        if( it != _session_data->end() ) {
            data.data = const_cast<char *>((it->second)->get_blob());
            data.length  = (it->second)->get_size();
            return_code = TDSC_SUCCESS;
        } else {
            sess_logger->error("TD_Session::get_object_value unknown object_id: {}", to_string(object_id));
            return_code = TDSC_UNKNOWN_OBJECT_ID;
        }

        return return_code;
    }

    TDSC_STATUS_CODE_t TD_Session::remove_object_by_id(const TDSC_OBJECT_ID_t object_id) {
        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;

        auto const it = _session_data->find(object_id);
        if( it != _session_data->end() ) {
            TD_Object * object = (it->second);
            if (object ) delete object;
            _session_data->erase(it);
            return_code = TDSC_SUCCESS;
        } else {
            return_code = TDSC_UNKNOWN_OBJECT_ID;
        }

        return return_code;
    }

    TD_Object * TD_Session::get_object_by_id(const TDSC_OBJECT_ID_t object_id) {
        TD_Object * object = nullptr;

        auto const it = _session_data->find(object_id);
        if( it != _session_data->end() ) {
            object = (it->second);
        }

        return object;
    }

    TD_Object * TD_Session::get_object_by_value(const char * value, const uint64_t length, TDSC_OBJECT_ID_t& object_id) {
        TD_Object * object_found = nullptr;
        TD_Object * object_search = nullptr;
        object_id = nil_uuid();

        for( auto const &it : (*_session_data) ) {
            object_search = it.second;
            if( (object_search->get_size() == length) && (memcmp(value, object_search->get_blob(), length) == 0) ) {
                object_found = object_search;
                object_id = it.first;
                break;
            }
        }

        return object_found;
    }
    
}
