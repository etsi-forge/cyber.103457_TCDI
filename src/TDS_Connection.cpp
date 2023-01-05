#include "TDS_TTLV_Tools.h"
#include "TDS_Constants.h"
#include "TDS_Connection.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace TDS {

    auto cnx_logger = spdlog::stdout_color_mt("connection");                    /*!< Connections related spdlog Logger */
    TD_Connection * TD_Connection::_the_connection = new TD_Connection();       /*!< TD_Connection singleton */

	TDSC_STATUS_CODE_t TD_Connection::set_connection_properties() { //uint64_t command_number) {

        TDSC_STATUS_CODE_t status_code = TDSC_SUCCESS;
        if(_session_manager == nullptr) _session_manager = new TD_Session_Manager();

		/* Output Data */
		_config_container_id = TDS_TTLV_Tools::gen_uuid();

		return status_code;
	}

	TDSC_STATUS_CODE_t TD_Connection::set_connection_properties(TDSC_LTD_ID_t const& ltd_id,
                                                                TDSC_LTD_ROLE_t const& ltd_role,
                                                                TDSC_CERT_COMMON_NAME_t const& cert_CN,
                                                                TDSC_NONCE_t const& nonce,
                                                                TDSC_DATA_t const& data ) {

        TDSC_STATUS_CODE_t status_code = TDSC_SUCCESS;
		_ltd_id 			= ltd_id;
		_ltd_role 			= ltd_role;
		_certificate_CN 	= cert_CN;

		_nonce.length   	= nonce.length;
		_nonce.data = new char[_nonce.length];
		memcpy(_nonce.data, nonce.data, _nonce.length);

		_data.length =  data.length;
		_data.data = new char[_data.length];
		memcpy(_data.data, data.data, _data.length);

        if( _certificate_CN.compare("TEST_TRUST_REFUSED") == 0 ) {
            status_code = TDSC_TRUST_REFUSED;
        } else {
            if(  _ltd_role.compare("TEST_UNKNOW_ROLE") == 0 ) {
                status_code = TDSC_UNKNOWN_ROLE;
            } else {
                if(_session_manager == nullptr) _session_manager = new TD_Session_Manager();
                _config_container_id = TDS_TTLV_Tools::gen_uuid();
            }
        }

		return status_code;
	}

    TDSC_STATUS_CODE_t TD_Connection::check_connection_trust(TDSC_CERT_COMMON_NAME_t const& cert_CN,
                                                             TDSC_NONCE_t const& nonce,
                                                             TDSC_DATA_t const& data) {
        TDSC_STATUS_CODE_t return_code = TDSC_SUCCESS;
        // Check Trust and returns either :
        // TDS_SUCCESS 
        // TDSC_TRUST_EXPIRED
        // TDSC_ATTESTATION_FAILED
        
        if( _certificate_CN.compare(cert_CN) != 0 || 
            _nonce.length != nonce.length  || 
            _data.length  != data.length ||
            memcmp(_nonce.data, nonce.data, _nonce.length) != 0 ||
            memcmp(_data.data, data.data, _data.length) != 0 ) {
                return_code = TDSC_ATTESTATION_FAILED;
        }

        return return_code;
    }

	TDSC_STATUS_CODE_t TD_Connection::_cleanup() {
        TDSC_STATUS_CODE_t return_code = TDSC_SUCCESS;
        if( _nonce.data != nullptr ) delete [] _nonce.data;
        if( _data.data != nullptr ) delete [] _data.data;
        
        return return_code;
	}

    TD_Connection::~TD_Connection() {
        if( _session_manager != nullptr ) {
            delete _session_manager;
            _session_manager = nullptr;
    	}
    	_cleanup();
    }

    TDSC_STATUS_CODE_t TD_Connection::close_connection() {
        TDSC_STATUS_CODE_t return_code = TDSC_GENERAL_FAILURE;
        _session_manager->clear_sessions();
    	return_code = _cleanup();

        return return_code;
    }

    void TD_Connection::dump_connection() {
        cnx_logger->info("----------------------------------------------------------");
        cnx_logger->info("Dumping connection content:");
        _session_manager->detailed_dump();
        cnx_logger->info("----------------------------------------------------------");
    }

}
