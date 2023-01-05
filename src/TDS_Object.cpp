#include <vector>
#include "TDS_Object.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

namespace TDS {

    auto object_logger = spdlog::stdout_color_mt("object"); /*!< Object related spdlog Logger */

    /* TD_Container */

    TD_Object::TD_Object(const char * object_blob, uint64_t object_size) {
        _object_size = object_size;
        _object_blob = new char[_object_size];
        memcpy(_object_blob, object_blob, _object_size);
    }

    TD_Object::~TD_Object() {
        if( _object_blob ) delete [] _object_blob;
        _object_blob = nullptr;
        _object_size = UINT64_C(0);
    }

    TD_Object::TD_Object(const TD_Object& original_object) {
        _object_size = original_object._object_size;
        _object_blob = new char[_object_size];
        memcpy(_object_blob, original_object._object_blob, _object_size);
    }

    void TD_Object::set_data(const char * object_blob, const uint64_t object_size) {
        _object_size = object_size;
        _object_blob = new char[_object_size];
        memcpy(_object_blob, object_blob, _object_size);
    }

    void TD_Object::dump(const std::string& tabs) {
        if( _object_size ) {
            std::vector<uint8_t> result((size_t)_object_size);
            for( std::size_t iter = 0; iter < (size_t)_object_size; iter++ ) {
                memcpy(&result[iter], _object_blob+iter, sizeof(uint8_t));
            }
            object_logger->info("{}Value: {:Xn}", tabs, spdlog::to_hex(std::begin(result), std::begin(result) + _object_size));
            object_logger->info("{}Size : {}", tabs, _object_size);
            object_logger->info("{}Ptr  : {:p}", tabs, (void*)(this));
        } else {
            object_logger->info("{}Value: NULL", tabs);
        }
    }

}
