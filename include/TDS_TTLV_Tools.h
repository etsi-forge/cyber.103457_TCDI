#ifndef TDS_TTLV_UTILS_H
#define TDS_TTLV_UTILS_H

/*!
* \file TDS_TTLV_Tools.h
* \brief
* \version 0.1
* \date 02/05/2020
*
* Sample implementation of ETSI 103457
*/

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include "TDS_CType.h"

/*! \namespace TDS
 *
 * namespace to regroup all Trusted Domain components and methods
 */

namespace TDS {

    /*! \class TDS_TTLV_Tools
     * ...
     *
     *  ...
     */

    class TDS_TTLV_Tools {
      public:
            /*!
             *  Generate a uuid - using boost framework
             *  \return a uuid
             */
		     static boost::uuids::uuid gen_uuid();

            /*!
             *  Decode a stream to a unicode string
             *  \param[in]  msg_string input message stream
             *  \param[in]  ttlv_tag the matching TAG
             *  \param[in]  ttlv_type the matching TYPE
             *  \param[out] shift_length the offset (number of bytes read) from the beginning of the input stream
             *  \param[out] placeholder the output unicode string
             *  \return bool
             * - True if unicode string was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Unicode_String(char *, const TDSC_TAG_t, const TDSC_TYPE_t, TDSC_LENGTH_t&, std::string&);

            /*!
             *  Decode a stream to a bytestring
             *  \param[in]  msg_string input message stream
             *  \param[in]  ttlv_tag the matching TAG
             *  \param[in]  ttlv_type the matching TYPE
             *  \param[out] shift_length the offset (number of bytes read) from the beginning of the input stream
             *  \param[out] placeholder the output bytestring
             *  \return bool
             * - True if unicode string was extracted
             * - False otherwise
             */
             static bool decode_TTLV_Byte_String(char *, const TDSC_TAG_t, const TDSC_TYPE_t, TDSC_LENGTH_t&, bytestring&);

            /*!
             *  Decode a TAG from a stream
             *  \param[in]  msg_string
             *  \param[out] placeholder
             *  \return bool
             * - True if TAG was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Tag(char *, TDSC_TAG_t&);

            /*!
             *  Decode a TYPE from a stream
             *  \param[in]  msg_string
             *  \param[out] placeholder
             *  \return bool
             * - True if TYPE was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Type(char *, TDSC_TYPE_t&);

            /*!
             *  Decode a LENGTH from a stream
             *  \param[in]  msg_string
             *  \param[out] placeholder
             *  \return bool
             * - True if LENGTH was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Length(char *, TDSC_LENGTH_t&);

            /*!
             *  Decode a Session ID from a stream
             *  \param[in]  msg_string
             *  \param[out] shift_length
             *  \param[out] placeholder
             *  \return bool
             * - True if Session Id was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Session_Id(char *, TDSC_LENGTH_t&, TDSC_SESSION_ID_t&);

            /*!
             *  Decode a Container ID from a stream
             *  \param[in]  msg_string
             *  \param[out] shift_length
             *  \param[out] placeholder
             *  \return bool
             * - True if Container Id was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Container_Id(char *, TDSC_LENGTH_t&, TDSC_CONTAINER_ID_t&);

            /*!
             *  Decode a Container Type from a stream
             *  \param[in]  msg_string
             *  \param[out] shift_length
             *  \param[out] placeholder
             *  \return bool
             * - True if Container rType was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Container_Type(char *, TDSC_LENGTH_t&, TDSC_CONTAINER_t&);

            /*!
             *  Decode a KEY_Type from a stream
             *  \param[in]  msg_string
             *  \param[out] shift_length
             *  \param[out] placeholder
             *  \return bool
             * - True if Key Type was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Key_Type(char *, TDSC_LENGTH_t&, TDSC_KEY_TYPE_t&);

            /*!
             *  Decode an Objec ID from a stream
             *  \param[in]  msg_string
             *  \param[out] shift_length
             *  \param[out] placeholder
             *  \return bool
             * - True if Object Id was extracted
             * - False otherwise
             */
            static bool decode_TTLV_Object_Id(char *, TDSC_LENGTH_t&, TDSC_OBJECT_ID_t&);

            /*!
             *  Decode a Size In Bytes  from a stream
             *  \param[in]  msg_string
             *  \param[out] shift_length
             *  \param[out] placeholder
             *  \return bool
             * - True if SizeInBytes was extracted
             * - False otherwise
             */
            static bool decode_TTLV_SizeInBytes(char *, TDSC_LENGTH_t&, TDSC_SIZE_IN_BYTES_t&);

            /*!
             *  Encode a Unicode String into a stream
             *  \param[in] tag_name
             *  \param[in] unicode_string
             *  \param[out] shift_length
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Unicode String was encoded
             * - False otherwise
             */
            static bool encode_Unicode_String_TTLV(const TDSC_TAG_t, const std::string&, TDSC_LENGTH_t&, char *);

            /*!
             *  Encode a ByteString into a stream
             *  \param[in]  tag_name
             *  \param[in]  byte_string
             *  \param[in]  msg_length
             *  \param[out] shift_length
             *  \param[in,out] placeholder
             *  \return bool
             * - True if ByteString was encoded
             * - False otherwise
             */
            static bool encode_Byte_String_TTLV(const TDSC_TAG_t,  const char *, const uint64_t, TDSC_LENGTH_t&, char *);

            /*!
             *  Encode a UUID into a stream
             *  \param[in]  tag_name
             *  \param[in]  byte_string
             *  \param[in]  msg_length
             *  \param[out] shift_length
             *  \param[in,out] placeholder
             *  \return bool
             * - True if ByteString was encoded
             * - False otherwise
             */            
            static bool encode_UUID_TTLV(const TDSC_TAG_t,  const char *, const uint64_t, TDSC_LENGTH_t&, char *);

            /*!
             *  Encode a TAG into a stream
             *  \param[in] tag_value
             *  \param[in,out] placeholder
             *  \return bool
             * - True if TTLV was encoded
             * - False otherwise
             */
            static bool encode_Tag_TTLV(const TDSC_TAG_t, char *);

            /*!
             *  Encode a TYPE into a stream
             *  \param[in] type_value
             *  \param[in,out] placeholder
             *  \return bool
             * - True if TYPE was encoded
             * - False otherwise
             */
            static bool encode_Type_TTLV(const TDSC_TYPE_t, char *);

            /*!
             *  Encode LENGTH into a stream
             *  \param[in] length_value
             *  \param[in,out] placeholder
             *  \return bool
             * - True if LENGTH was encoded
             * - False otherwise
             */
            static bool encode_Length_TTLV(const TDSC_LENGTH_t, char *);

            /*!
             *  Encode a Session Id into a stream
             *  \param[in] session_id
             *  \param[out] shift_length
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Session Id was encoded
             * - False otherwise
             */
            static bool encode_Session_Id_TTLV(const TDSC_SESSION_ID_t&, TDSC_LENGTH_t&, char *);    

             /*!
             *  Encode an Object Id into a stream
             *  \param[in] object_id
             *  \param[out] shift_length
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Object Id was encoded
             * - False otherwise
             */
            static bool encode_Object_Id_TTLV(const TDSC_OBJECT_ID_t&, TDSC_LENGTH_t&,  char *);

            /*!
             *  Encode a Container Id into a stream
             *  \param[in] container_id
             *  \param[out] shift_length
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Container Id was encoded
             * - False otherwise
             */      
            static bool encode_Container_Id_TTLV(const TDSC_CONTAINER_ID_t, TDSC_LENGTH_t&, char *);

            /*!
             *  Encode Container Type into a stream
             *  \param[in] container_type
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Container Type was encoded
             * - False otherwise
             */
            static bool encode_Container_Type_TTLV(const TDSC_CONTAINER_t, char *);

            /*!
             *  Encode a Key Type into a stream
             *  \param[in] key_type
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Key Type was encoded
             * - False otherwise
             */
            static bool encode_Key_Type_TTLV(const TDSC_KEY_TYPE_t, char *);

            /*!
             *  Encode a Size In Bytes into a stream
             *  \param[in] size_in_bytes
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Size In Bytes was encoded
             * - False otherwise
             */  
            static bool encode_SizeInBytes_TTLV(const TDSC_SIZE_IN_BYTES_t, char *);

            /*!
             *  Encode Command Type into a stream
             *  \param[in] command_type
             *  \param[in,out] placeholder
             *  \return bool
             * - True if Command Type was encoded
             * - False otherwise
             */
            static bool encode_Command_Type(const TDSC_COMMAND_t, char *);

            /*!
             *  Dump a command content from its stream
             *  \param[in] msg
             *  \param[in] msg_length
             */
            static void dump_Command(char *, uint64_t);

            /*!
             *  Dump a TYPE litteral from its numerical representation
             *  \param[in] msg_type
             *  \return std::string
             */
            static std::string TYPE_to_string(const TDSC_TYPE_t);

            /*!
             *  Dump a TAG litteral from its numerical representation
             *  \param[in] msg_tag
             *  \return std::string
             */
            static std::string TAG_to_string(const TDSC_TAG_t);

            /*!
             *  Dump a Command litteral from its numerical representation
             *  \param[in] cmd_type
             *  \return std::string
             */
            static std::string CMD_to_string(const uint8_t cmd_type);

            /*!
             *  Create an uuid from its bytrestring representation
             *  \param[in] bytestring
             *  \return uuid
             */
            static uuid get_id_from_bytestring(const bytestring&);

            /*!
             *  Create an uuid from its string representation
             *  \param[in] uuid_string
             *  \return uuid
             */            
            static uuid get_id_from_string(const std::string&);

      private:

		    static boost::uuids::random_generator _uuid_generator;
            static bool _decode_TTLV_uint8(char *, uint8_t&);
            static bool _decode_TTLV_uint16(char *, uint16_t&);
            static bool _decode_TTLV_uint64(char *, uint64_t&);
		    static bool _decode_TTLV_bytestring(char *, bytestring&);
            static bool _decode_TTLV_string(char *, uint64_t, std::string&);
            static bool _encode_uint8_TTLV(const uint8_t, char*);
            static bool _encode_uint16_TTLV(const uint16_t, char*);
            static bool _encode_uint64_TTLV(const uint64_t, char*);
            static bool _encode_bytestring_TTLV(const char *, uint64_t, char *);
            static bool _encode_string_TTLV(std::string&, char *);

            static void _bytestring_to_uuid(bytestring&, boost::uuids::uuid&);

	};
}

#endif
