#ifndef TDSC_OBJECT_H
#define TDSC_OBJECT_H

/*!
* \file TDS_Object.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include <cstdint>
#include <cstring>
#include <string>

using namespace std;

namespace TDS {

    /*! \class TD_Object
    * ...
    *
    *  ...
    */

    class TD_Object {

        public:

            /*!
             *  Constructor
             */
            TD_Object() {};

            /*!
             *  Constructor
             *  \param[in] object_blob  Pointer to the content of the object
             *  \param[in] object_size  Size of the object content
             */
            TD_Object(const char *, uint64_t);

            /*!
             *  Destructor
             */
            virtual ~TD_Object();

            /*!
             *  Copy constructor
             */
            TD_Object(const TD_Object&);

            /*!
             *  se_td_data
             *  \param[in] object_blob  Pointer to the content of the object
             *  \param[in] object_size  Size of the object content
             */
            void set_data(const char *, const uint64_t);

            /*!
             *  get_blob
             *  \return Pointer to the content of the object
             */
            const char * get_blob() { return _object_blob; };

            /*!
             *  get_size
             *  \return Size of the object content
             */
            uint64_t  get_size() { return _object_size; };

            /*!
             *  is_rootd_object
             *  \return False if the TD_Object is on a TD_Container and not accessible directly from its id, False otherwise
             */
            virtual bool is_root_object() { return true; };

            /*!
             *  dump
             *  \param[in] tabs Dump trace prefix
             */
            virtual void dump(const std::string&);

        private:

            char      * _object_blob = nullptr;         /*!< Object content */
            uint64_t    _object_size = UINT64_C(0);     /*!< Size of the Object content */
    };
}

#endif
