#ifndef TDSC_CTYPES_H
#define TDSC_CTYPES_H

/*!
* \file TDS_CType.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include <string>
#include <utility>
#include <map>
#include <list>
#include <cstdint>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "TDS_Constants.h"

using namespace std;
using namespace boost::uuids;

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /* Forward declarations */
    class TD_Object;
    class TD_Session;

    /**
     * \ struct bytestring
     */
    typedef struct {
        uint64_t length = 0;                                                /*!< bytestring length */
        char *   data   = nullptr;                                          /*!< bytestring content */
    } bytestring;

    typedef uint8_t                         TDSC_TAG_t;                     /*!< TTLV TAG member    */
    typedef uint16_t                        TDSC_TYPE_t;                    /*!< TTLV TYPE member   */
    typedef uint64_t                        TDSC_LENGTH_t;                  /*!< TTLV LENGTH member */

    typedef uint8_t                         TDSC_MESSAGE_ID_t;              /*!< Message identifier */

    typedef uint8_t                         TDSC_CONTAINER_t;               /*!< Unique identifier for a database or a file in the MTD */
    typedef uint8_t                         TDSC_COMMAND_t;                 /*!< Command identifier */

    typedef string                          TDSC_LTD_ID_t;                  /*!< LTD identifier generated by the MTD */
    typedef string                          TDSC_LTD_ROLE_t;                /*!< Information about the LTD entity in the untrusted domain to the MTD enabling the MTD to behave accordingly at application level */
    typedef string                          TDSC_CERT_COMMON_NAME_t;        /*!< Certificate common Name  */

    /* Should be uuids coded in char[16] */
    typedef uuid                            TDSC_OBJECT_ID_t;               /*!< Unique Object identifier */
    typedef uuid                            TDSC_SESSION_ID_t;              /*!< Unique identifier for a Session */

    typedef uuid                            TDSC_CONTAINER_ID_t;            /*!< Unique identifier for a database or a file in the MTD */
    typedef string                          TDSC_CONTAINER_NAME_t;          /*!< Identifier of a secure storage container */
    typedef bytestring                      TDSC_SIGNED_DATA_t;             /*!< Attestation of state integrity of the LTD entity computed as Data = SIGN-RSA (hash)\n
                                                                                 with hash being the cryptographic hash of a reference measurements appended by the Nonce value to attest */

    typedef pair<bytestring,bytestring>     TDSC_DB_KEYVALUE_t;             /*!< Pair (DB_Key, DB_Value) structured type. */
    typedef bytestring                      TDSC_DB_KEY_t;                  /*!< TDSC_DB_KEY_t */
    typedef bytestring                      TDSC_DB_VALUE_t;                /*!< TDSC_DB_VALUE_t */
    typedef uint8_t                         TDSC_COMMAND_TYPE_t;            /*!< TDSC_COMMAND_TYPE_t */

    /*! Status Code enumeration */
    typedef enum status_code : uint16_t {                                   
        TDSC_SUCCESS                        = 0x00,                            /*!< Function succeeded  */
        TDSC_GENERAL_FAILURE                = 0x01,                            /*!< Generic failure code */
        TDSC_SESSION_ID_ALREADY_OPENED      = 0x02,                            /*!< Session has already been created for the current Connection */
        TDSC_TOO_MANY_EXISTING_SESSIONS     = 0x03,                            /*!< The maximum concurrent sessions supported by the MTD is reached */
        TDSC_ON_GOING_PROCESSES             = 0x04,                            /*!< Processes are still running on the MTD */
        TDSC_TOO_MANY_OPENED_CONNECTIONS    = 0x05,                            /*!< The connection is refused by the MTD */
        
        TDSC_TRUST_REFUSED                  = 0x10,                            /*!< The connection is refused by the MTD because the trust of the LTD cannot be established */
        TDSC_TRUST_EXPIRED                  = 0x11,                           /*!< Trust needs to be renewed between LTD and MTD */
        
        TDSC_UNKNOWN_ROLE                   = 0x20,                           /*!< The LTD role is not known by the MTD */
        
        TDSC_UNKNOWN_SESSION_ID             = 0x30,                          /*!< Session-Id is not known by the MTD */
        TDSC_UNKNOWN_OBJECT_ID              = 0x31,                          /*!< Object-Id is not known by the MTD */
        TDSC_UNKNOWN_CONTAINER_ID           = 0x32,                          /*!< Container-Id is not known by the MTD  */
        TDSC_UNKNOWN_KEY_ID                 = 0x33,                          /*!< Key-Id is unknown in the MTD  */
        TDSC_UNKNOWN_ARCHIVE_ID             = 0x34,                          /*!< Unknown archive id */

        TDSC_OBJECT_CREATION_FAILED         = 0x40,                          /*!< Unable to create new object  */
        TDSC_ARCHIVE_CREATION_FAILED        = 0x41,                          /*!< Archive creation failed */
        TDSC_CONTAINER_CREATION_FAILED      = 0x42,                          /*!< Container creation failed (Storage) */

        TDSC_CONTAINER_TYPE_NOT_SUPPORTED   = 0x50,                          /*!< Container-Type is not supported  */
        TDSC_CONTAINER_WRITE_ONLY           = 0x51,                          /*!< Container-Id references an Archive Container  */
        TDSC_CONTAINER_NAME_ALREADY_EXISTS  = 0x52,                          /*!< Container-Name already in use  */
        TDSC_CONTAINER_NAME_NOT_FOUND       = 0x53,                          /*!< No container named Container-Name found  */
        TDSC_DATA_TYPE_NOT_SUPPORTED        = 0x54,                          /*!< Data provided by the LTD mismatch MTD Container's data type */
        TDSC_STORAGE_FULL                   = 0x55,                          /*!< MTD allocated storage is full  */
        TDSC_STORAGE_BUSY                   = 0x56,                          /*!< Storage/Archive process is still busy on the MTD  */

        TDSC_UNKNWON_KEY                    = 0x60,                          /*!< Key is unknown in the MTD Container  */
        TDSC_UNKNOWN_KEY_TYPE               = 0x61,                          /*!< Requested key type is not supported by the MTD  */
        TDSC_KEY_SIZE_NOT_SUPPORTED         = 0x62,                          /*!< Requested key size is not supported by the MTD  */

        TDSC_VALUE_NOT_FOUND                = 0x70,                          /*!< Searched value not found in the MTD  */
        TDSC_NOT_ENOUGH_ENTROPY             = 0x71,                          /*!< No enough entropy to fulfill an entropy request  */
        TDSC_ATTESTATION_FAILED             = 0x72,                          /*!< Remote attestation failed  */

    } TDSC_STATUS_CODE_t;                                                  

    typedef uint8_t                         TDSC_KEY_TYPE_t;                /*!< TDSC_KEY_TYPE_t */

    typedef bytestring                      TDSC_SUBJECT_t;                 /*!< TDSC_SUBJECT_t */
    typedef bytestring                      TDSC_CONTEXT_t;                 /*!< TDSC_CONTEXT_t */

    typedef pair<TDSC_SUBJECT_t,TDSC_CONTEXT_t> TDSC_EVENT_t;               /*!< Pair (subject,context) structured type. */

    typedef uint64_t                        TDSC_SIZE_IN_BYTES_t;           /*!< Size in bytes type*/
    typedef bytestring                      TDSC_DATA_t;                    /*!< Data type*/
    typedef bytestring                      TDSC_NONCE_t;                   /*!< Used to convey MTD generated nonce values. */
    typedef string                          TDSC_PASSPHRASE_t;              /*!< Passphrase used in cryptographic context */

    typedef map<TDSC_SESSION_ID_t, TD_Session *> TDSC_SESSION_MAP_t;        /*!< TDSC_SESSION_MAP_t*/
    typedef map<TDSC_OBJECT_ID_t, TD_Object *>   TDSC_SESSION_DATA_t;       /*!< TDSC_SESSION_DATA_t*/
    typedef map<TDSC_OBJECT_ID_t, TD_Object *>   TDSC_CONTAINER_DATA_t;     /*!< TDSC_CONTAINER_DATA_t*/
    
    typedef uint8_t                         TDSC_TRUST_t;                   /*!< Trusted Session */
}

#endif
