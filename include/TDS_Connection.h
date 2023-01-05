#ifndef TDS_CONNECTION_H
#define TDS_CONNECTION_H

/*!
* \file TDS_Connection.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include "TDS_CType.h"
#include "TDS_Session_Manager.h"

using namespace std;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TD_Connection
    * 
    *  This class is intended manage the connection to the MTD
    */

    class TD_Connection {
        public:

            /*!
             *  Constructor
             */
            TD_Connection() {};

            /*!
             *  Destructor
             */
             ~TD_Connection();

            /*!
             *  Retrieve the _the_connection\n
             *  _the_connection follows the singleton_pattern and is unique 
             *  single connection and multiple session
             *  \return TD_Connection * The connection singleton
             */
            static TD_Connection * get_connection() { return _the_connection; };

            /*!
             *  Set the connection _command_number property
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_ROLE
             * - TDSC_TRUST_REFUSED
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t set_connection_properties(); 

            /*!
             *  set_connection_properties
             *  \param[in] ltd_id Identifier of the requesting entity
             *  \param[in] ltd_role Role of the requesting entity
             *  \param[in] cert_CN The certificate common name CN associated to a RSA TPM-Key used by LTD 
             *  \param[in] nonce Nonce value computed upon connection by the MTD 
             *  \param[in] data MTD shall verify the signature to trust the LTD and accept the connection 
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_UNKNOWN_ROLE
             * - TDSC_TRUST_REFUSED
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t set_connection_properties(TDSC_LTD_ID_t const& ,
                                                                TDSC_LTD_ROLE_t const& ,
                                                                TDSC_CERT_COMMON_NAME_t const& ,
                                                                TDSC_NONCE_t const& ,
                                                                TDSC_DATA_t const&);

            /*!
             *  Close the connection
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t close_connection();

            /*!
             *  Retrieve the _session_manager associated to the connection
             *  \return TD_Session_Manager * The session manager associated to the connection
             */
            TD_Session_Manager * get_session_manager() { return _session_manager; };

            /*!
             *  Retrieve the configuration container associated to the connection
             *  \param[out] container_id
             */
            void get_container_id(TDSC_CONTAINER_ID_t& container_id) { container_id = _config_container_id; };  

            /*!
             *  Check if the trust link between the MTD and the LTD is still valid
             *  \return TDSC_STATUS_CODE_t
             * - TDSC_SUCCESS
             * - TDSC_GENERAL_FAILURE
             */
            TDSC_STATUS_CODE_t check_connection_trust(TDSC_CERT_COMMON_NAME_t const& ,
                                                                TDSC_NONCE_t const& ,
                                                                TDSC_DATA_t const& );

            /*!
             *  Helper : In depth dump of the connection content
             */
            void dump_connection();

        private:

            TDSC_STATUS_CODE_t _cleanup();

            TDSC_LTD_ID_t               _ltd_id;                    /*!< Identifier of the requesting entity */
            TDSC_LTD_ROLE_t             _ltd_role;                  /*!< Role of the requesting entity */
            TDSC_CERT_COMMON_NAME_t     _certificate_CN;            /*!< The certificate common name CN associated to a RSA TPM-Key used by LTD */
            TDSC_NONCE_t                _nonce;                     /*!< Nonce value computed upon connection by the MTD */
            TDSC_DATA_t                 _data;                      /*!< MTD shall verify the signature to trust the LTD and accept the connection */
            TD_Session_Manager        * _session_manager = NULL;    /*!< The session manager */
            TDSC_CONTAINER_ID_t         _config_container_id;       /*!< The configuration container id */

            static TD_Connection      * _the_connection;            /*!< the TD_Connection singleton */
    };
}

#endif
