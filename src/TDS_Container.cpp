#include "TDS_TTLV_Tools.h"
#include "TDS_Container.h"
#include "TDS_Constants.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

namespace TDS {

    auto ctn_logger = spdlog::stdout_color_mt("container"); /*!< Container related spdlog Logger */

    /* TD_Container */

    TD_Container::TD_Container() : TD_Object() {
        _container_data = new TDSC_CONTAINER_DATA_t();
    }

    TD_Container::TD_Container(const char * object_blob, uint64_t object_size) : TD_Object(object_blob,object_size) {
        _container_data = new TDSC_CONTAINER_DATA_t();
    }

    TD_Container::~TD_Container() {
        for( auto const& it : (*_container_data) ) {
            delete it.second;
        }
        _container_data->clear();
        delete _container_data;
    }

    TDSC_OBJECT_ID_t TD_Container::add_object(TD_Object * object) {
        TDSC_OBJECT_ID_t object_uuid = TDS_TTLV_Tools::gen_uuid();
        auto return_insert = _container_data->insert(make_pair(object_uuid, object));
        if( return_insert.second == false ) object_uuid = nil_uuid();
        return object_uuid;
    }

    TDSC_OBJECT_ID_t TD_Container::add_object(std::string& object_uuid_string, TD_Object * object) {
        TDSC_OBJECT_ID_t object_uuid = TDS_TTLV_Tools::get_id_from_string(object_uuid_string);
        auto return_insert = _container_data->insert(make_pair(object_uuid, object));
        if( return_insert.second == false ) object_uuid = nil_uuid();
        return object_uuid;
    }

    TD_Object * TD_Container::get_object_by_id(const TDSC_OBJECT_ID_t object_id) {
        TD_Object * t_object = nullptr;
        auto it = _container_data->find(object_id);
        if( it != _container_data->end() ) {
            t_object = (it->second);
        }

        return t_object;
    }

    TDSC_OBJECT_ID_t TD_Container::get_object_id_by_value(const TDSC_DATA_t& value) {
        TDSC_OBJECT_ID_t t_object_id = nil_uuid();
        
        for( auto const& it : (*_container_data) ) {
            if( (it.second)->get_size() == value.length && memcmp((it.second)->get_blob(), value.data, value.length) == 0 ) {
                t_object_id = it.first;
                break;
            } 
        }        
        
        return t_object_id;
    }

    void TD_Container::dump(std::string& tabs) {
        TD_Object::dump(tabs);
        ctn_logger->info("{}Container content:", tabs);

        for( auto const& it : (*_container_data) ) {
            ctn_logger->info("{}\tObject registered: {}", tabs, to_string(it.first));
            uint64_t blob_size = (it.second)->get_size();
            if( blob_size ) {
                std::vector<uint8_t> result((size_t)blob_size);
                const char * blob = (it.second)->get_blob();
                for( unsigned int ii = 0; ii < (size_t)blob_size; ii++ ) {
                    memcpy(&result[ii], blob+ii, sizeof(uint8_t));
                }
                ctn_logger->info("{}\tValue: {:Xn}", tabs, spdlog::to_hex(std::begin(result), std::begin(result) + blob_size));
                ctn_logger->info("{}\tSize : {}", tabs, blob_size);
                ctn_logger->info("{}\tPtr  : {:p}", tabs, (void*)(it.second));
                
            } else ctn_logger->info("{}\tValue: NULL", tabs);
        }
    }

}
