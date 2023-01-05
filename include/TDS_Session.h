#ifndef TDS_SESSION_H
#define TDS_SESSION_H

/*!
* \file TDS_Session.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Object.h"
#include <vector>
#include <map>

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    class TD_Connection;

    /*! \class TD_Session
    * ...
    *
    *  ...
    */

    class TD_Session {
        public:

            /*!
             *  Constructor
             */
            TD_Session();

            /*!
             *  Destructor
             */
            ~TD_Session();

            /*!
             *  get_session_id
             *  \return TDSC_SESSION_ID_t
             */
            const TDSC_SESSION_ID_t get_session_id() { return _session_id; };

            /*!
             *  add_object
             *  \param[in] object
             *  \return TDSC_OBJECT_ID_t
             */
            TDSC_OBJECT_ID_t add_object(TD_Object *);

            /*!
             *  dump_session
             */
            void dump_session();

            /*!
             *  remove_object_by_id
             *  \param[in] object_id
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t remove_object_by_id(const TDSC_OBJECT_ID_t);

            /*!
             *  get_object_by_id
             *  \param[in] object_id
             *  \return TD_Object *
             */
            TD_Object * get_object_by_id(const TDSC_OBJECT_ID_t);

            /*!
             *  get_object_by_value
             *  \param[in] value
             *  \param[in] length
             *  \param[out] object_id
             *  \return TD_Object *
             */
            TD_Object * get_object_by_value(const char *, const uint64_t, TDSC_OBJECT_ID_t&);

            /*!
             *  get_new_object_id
             *  \return uuid
             */
            uuid get_new_object_id();

            /*!
             *  set_object_value
             *  \param[in] object_id
             *  \param[in] data
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t set_object_value(const TDSC_OBJECT_ID_t, const TDSC_DATA_t&);

            /*!
             *  get_object_value
             *  Returns an ByteString pointing to the object value content
             *  \param[in] object_id
             *  \param[out] data
             *  \return TDSC_STATUS_CODE_t
             */
            TDSC_STATUS_CODE_t get_object_value(const TDSC_OBJECT_ID_t, TDSC_DATA_t&);

        private:

            TDSC_SESSION_ID_t       _session_id;                /*!< Data*/
            TDSC_SESSION_DATA_t   * _session_data   = nullptr;  /*!< Data*/
    };
}

#endif
