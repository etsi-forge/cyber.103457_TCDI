#ifndef TDSC_CONTAINER_H
#define TDSC_CONTAINER_H

/*!
* \file TDS_Container.h
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_Object.h"

using namespace std;

namespace TDS {

    /*! \class TD_Container
    * ...
    *
    *  ...
    */

    class TD_Container : public TD_Object {
        public:
            /*!
             *  Constructor
             */
            TD_Container();

            /*!
             *  Constructor
             *  \param[in] object_blob
             *  \param[in] object_size
             */
            TD_Container(const char *, uint64_t);

            /*!
             *  Destructor
             */
            virtual ~TD_Container();

            /*!
             *  is_root_object
             *  \return bool
             */
            bool is_root_object() override { return false; };

            /*!
             *  add_object
             *  \param[in] object
             *  \return TDSC_OBJECT_ID_t
             */
            TDSC_OBJECT_ID_t add_object(TD_Object *);

            /*!
             *  add_object
             *  \param[in] object_uuid_string in string standard format
             *  \param[in] object
             *  \return TDSC_OBJECT_ID_t
             */
            TDSC_OBJECT_ID_t add_object(std::string&, TD_Object *);            

            /*!
             *  get_object_by_id
             *  \param[in] object_id
             *  \return TD_Object *
             */
            TD_Object * get_object_by_id(const TDSC_OBJECT_ID_t);

            /*!
             *  get_object_by_value
             *  \param[in] value
             *  \return TD_Object *
             */
            TDSC_OBJECT_ID_t get_object_id_by_value(const TDSC_DATA_t&);

            /*!
             *  set_storage_filename
             *  \param[in] storage_filename
             */
            void set_storage_filename(std::string& storage_filename) { _storage_filename = storage_filename; };

            /*!
             *  get_storage_filename
             *  \return storage_filename
             */
            std::string get_storage_filename() { return _storage_filename; };

            /*!
             *  dump
             *  \param[in] tabs
             */
            void dump(std::string&);

        private:

            TDSC_CONTAINER_DATA_t * _container_data = nullptr;  /*!< Data*/
            static TDSC_OBJECT_ID_t _object_id;                 /*!< Data*/
            std::string             _storage_filename;          /*!< Data*/
    };
}

#endif

