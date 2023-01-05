#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <iostream>
#include <unistd.h>

#include <botan/version.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/base_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/filesystem.hpp>

#include "TDS_CType.h"
#include "TDS_Commands.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_Container.h"

#include "ConnectionCommands.h"
#include "ObjectCommands.h"
#include "CryptoCommands.h"
#include "ArchiveCommands.h"
#include "StorageCommands.h"
#include "SessionCommands.h"

using namespace std;
using namespace boost::uuids;
//using namespace boost::unit_test;

auto logger = spdlog::stdout_color_mt("console");
boost::uuids::random_generator _uuid_generator; 

// Forward Declarations
void bs_string(TDS::bytestring object, std::string& result);
void rnd_string(TDS::bytestring object, std::string& result);
void ts_string(TDS::bytestring object, std::string& result);
void string_bs(std::string& object_string, TDS::bytestring& object_bytestring);


void bs_string(TDS::bytestring object, std::string& result) {
	char object_char[1024];
	memset(&object_char[0], 0x0, 1024);
	memcpy(&object_char[0], object.data, object.length);
	result = object_char;
}

void rnd_string(TDS::bytestring object, std::string& result) {
	result = "";
	uint8_t value;
	for( uint64_t i=0; i< object.length; i++ ) {
		value = object.data[i];
		result.append(to_string(value));
	}
}

void ts_string(TDS::bytestring object, std::string& result) {
	int64_t ts_object;
	memcpy(&ts_object, object.data, sizeof(int64_t));
	result = to_string(ts_object);
}

void string_bs(std::string& object_string, TDS::bytestring& object_bytestring) {
    if( object_bytestring.data ) delete [] object_bytestring.data;
    object_bytestring.length = object_string.length();
    object_bytestring.data = new char[object_bytestring.length];
    memcpy(&object_bytestring.data[0], object_string.c_str(), object_bytestring.length);
}


TEST_CASE( "Connection", "[Connection]" ) {

    spdlog::set_pattern("[%H:%I:%M:%S.%e][%-5!l][%-7!n] %^%v%$");
    spdlog::set_level(spdlog::level::critical);

    std::string LTD_Id_string    = "LTD-Id String";
    std::string LTD_Role_string  = "LTD-Role String";
    std::string LTD_CN_string    = "Certificate CN String";
    std::string LTD_Nonce_string = "Nonce ByteString";
    std::string LTD_Data_string  = "Data ByteString";

    TDS::TDSC_NONCE_t LTD_Nonce_ByteString;
    TDS::TDSC_DATA_t LTD_Data_ByteString;

    string_bs(LTD_Nonce_string, LTD_Nonce_ByteString);
    string_bs(LTD_Data_string, LTD_Data_ByteString);

    SECTION("Opening connection with zero length data") {
    	std::string zero_length_string = "";
    	TDS::TDSC_NONCE_t Nonce_ZeroByteString;
    	TDS::TDSC_DATA_t Data_ZeroByteString;
	
	    string_bs(zero_length_string, Nonce_ZeroByteString);
    	string_bs(zero_length_string, Data_ZeroByteString);

        REQUIRE( OpenConnection_command( zero_length_string, zero_length_string, zero_length_string, Nonce_ZeroByteString, Data_ZeroByteString) == true);
    }

    SECTION("Opening connection with zero lengths") {
    	std::string zero_length_string = "";
    	TDS::TDSC_NONCE_t Nonce_ZeroByteString;
    	TDS::TDSC_DATA_t Data_ZeroByteString;
	
	    string_bs(zero_length_string, Nonce_ZeroByteString);
    	string_bs(zero_length_string, Data_ZeroByteString);

        REQUIRE( OpenConnection_command( zero_length_string, zero_length_string, zero_length_string, Nonce_ZeroByteString, Data_ZeroByteString) == true);
    }

    SECTION("Opening connection with Data length out of bound") {
    	TDS::TDSC_DATA_t Data_OutOfBoundByteString;
	
    	string_bs(LTD_Data_string, Data_OutOfBoundByteString);

    	Data_OutOfBoundByteString.length = Data_OutOfBoundByteString.length + 10;

        REQUIRE( OpenConnection_command( LTD_Id_string, LTD_Role_string, LTD_CN_string, LTD_Nonce_ByteString, Data_OutOfBoundByteString) == true);
    }

    SECTION("Opening connection") {
        REQUIRE( OpenConnection_command( LTD_Id_string, LTD_Role_string, LTD_CN_string, LTD_Nonce_ByteString, LTD_Data_ByteString) == true);
    }
}

TDS::TDSC_SESSION_ID_t the_session_id1;
TDS::TDSC_SESSION_ID_t the_session_id2;
TDS::TDSC_SESSION_ID_t the_session_id3;
TDS::TDSC_SESSION_ID_t the_session_id4;

TDS::TDSC_CONTAINER_ID_t the_container_id1;
TDS::TDSC_CONTAINER_ID_t the_container_id2;

TDS::TDSC_OBJECT_ID_t the_object_id;
TDS::TDSC_OBJECT_ID_t the_object_id11;
TDS::TDSC_OBJECT_ID_t the_object_id21;
TDS::TDSC_OBJECT_ID_t the_object_id22;
TDS::TDSC_OBJECT_ID_t the_object_id31;
TDS::TDSC_OBJECT_ID_t the_object_id41;

TDS::TDSC_OBJECT_ID_t the_object_id_reference;
TDS::TDSC_OBJECT_ID_t the_object_id_candidate;

TDS::TDSC_DATA_t object_bytestring;
std::string object_value_string;
std::string object_reference_string;

std::string result_string1;
std::string result_string2;

std::string archive_string;

std::string storage_name;
std::string storage_filename;
std::string storage_string;

size_t storage_size1;
size_t storage_size2;

TEST_CASE("Sessions", "[Sessions]") {

    SECTION("Creating sessions") {
        REQUIRE( CreateSession_Command(the_session_id1) == true );  
        REQUIRE( CreateSession_Command(the_session_id2) == true );  
        REQUIRE( CreateSession_Command(the_session_id3) == true );  
        REQUIRE( CreateSession_Command(the_session_id4) == true );
    }
    
    SECTION("Closing one session") {
        REQUIRE( CloseSession_Command(the_session_id4) == true );
    }

    SECTION("Closing a session already closed") {
        REQUIRE( CloseSession_Command(the_session_id4) == false );
    }

    SECTION("Closing a session that does not exist") {
        TDS::TDSC_SESSION_ID_t the_session_id = _uuid_generator();
        REQUIRE( CloseSession_Command(the_session_id) == false );
    }
}

TEST_CASE("Objects", "[Sessions][Object]") {

    SECTION("Create Objects") {
        REQUIRE( CreateObject_Command(the_session_id1, the_object_id11) == true );
        REQUIRE( CreateObject_Command(the_session_id2, the_object_id21) == true );
        REQUIRE( CreateObject_Command(the_session_id2, the_object_id22) == true );
        REQUIRE( CreateObject_Command(the_session_id3, the_object_id31) == true );
    }

    SECTION("Create object in closed session") {
        REQUIRE( CreateObject_Command(the_session_id4, the_object_id41) == false );
    }

    SECTION("Put Objects Values") {
        object_value_string = "Object11 ByteString";
        string_bs(object_value_string, object_bytestring);
        REQUIRE( PutObjectValue_Command(the_session_id1, the_object_id11, object_bytestring) == true );

        object_value_string = "Object21 ByteString";
        string_bs(object_value_string, object_bytestring);
        REQUIRE( PutObjectValue_Command(the_session_id2, the_object_id21, object_bytestring) == true );
    }

    SECTION("Put Object Value to an object in the wrong session") {
        object_value_string = "Object22 ByteString";
        string_bs(object_value_string, object_bytestring);
        REQUIRE( PutObjectValue_Command(the_session_id1, the_object_id22, object_bytestring) == false );
    }

    SECTION("Put Object Value to a non existing object") {
        object_value_string = "ObjectXX ByteString";
        string_bs(object_value_string, object_bytestring);
        REQUIRE( PutObjectValue_Command(the_session_id2, uuid(), object_bytestring) == false );
    }

    SECTION("Get Objects Values") {
        object_reference_string = "Object11 ByteString";
        REQUIRE( GetObjectValue_Command(the_session_id1, the_object_id11, object_bytestring) == true );
        bs_string(object_bytestring, object_value_string);
        REQUIRE( object_reference_string.compare(object_value_string) == 0 );

        object_reference_string = "Object21 ByteString";
        REQUIRE( GetObjectValue_Command(the_session_id2, the_object_id21, object_bytestring) == true );
        bs_string(object_bytestring, object_value_string);
        REQUIRE( object_reference_string.compare(object_value_string) == 0 );
    }

    SECTION("Get Object Value in the wrong session") {
        object_reference_string = "Object22 ByteString";
        REQUIRE( GetObjectValue_Command(the_session_id1, the_object_id22, object_bytestring) == false );
        REQUIRE( object_bytestring.length == 0 );
    }

    SECTION("Get Object Value from a non existing object") {
        object_reference_string = "ObjectXX ByteString";
        REQUIRE( GetObjectValue_Command(the_session_id2, uuid(), object_bytestring) == false );
        REQUIRE( object_bytestring.length == 0 );
    }

    SECTION("Get Object Value from a closed Session") {
        object_reference_string = "ObjectXX ByteString";
        REQUIRE( GetObjectValue_Command(the_session_id4, the_object_id41, object_bytestring) == false );
        REQUIRE( object_bytestring.length == 0 );
    }    
}

TEST_CASE("Crypto", "[Crypto][Object]") {

    SECTION("Get Trusted TimeStamp") {
        REQUIRE( GetTrustedTimestamping_Command(the_session_id2, the_object_id_reference) == true );
        REQUIRE( GetObjectValue_Command(the_session_id2, the_object_id_reference, object_bytestring) == true );
        ts_string(object_bytestring, result_string1);
        REQUIRE( object_bytestring.length > 0);
    }

    SECTION("Get Trusted TimeStamp from a closed Session") {
        REQUIRE( GetTrustedTimestamping_Command(the_session_id4, the_object_id_reference) == false );
    }    

    SECTION("Compare Trusted TimeStamp") {
        unsigned int usecs = 1000;
        usleep(usecs);
        REQUIRE( GetTrustedTimestamping_Command(the_session_id2, the_object_id_candidate) == true );
        REQUIRE( GetObjectValue_Command(the_session_id2, the_object_id_candidate, object_bytestring) == true );
        ts_string(object_bytestring, result_string2);
        REQUIRE( result_string2.compare(result_string1) != 0 );
    }    

    SECTION("Get Random") {
        REQUIRE( GetRandom_Command(the_session_id2, 10, the_object_id_reference) == true );
        REQUIRE( GetObjectValue_Command(the_session_id2, the_object_id_reference, object_bytestring) == true );
        rnd_string(object_bytestring, result_string1);
        REQUIRE( object_bytestring.length == 20 );
    }

    SECTION("Get Random from a closed Session") {
        REQUIRE(  GetRandom_Command(the_session_id4, 10, the_object_id_reference) == false );
    }      

    SECTION("Compare Random same size") {
        REQUIRE( GetRandom_Command(the_session_id2, 10, the_object_id_candidate) == true );
        REQUIRE( GetObjectValue_Command(the_session_id2, the_object_id_candidate, object_bytestring) == true) ;
        rnd_string(object_bytestring, result_string2);
        REQUIRE( result_string2.compare(result_string1) != 0 );
    }

    SECTION("Compare Random different sizes") {
        REQUIRE( GetRandom_Command(the_session_id2, 12, the_object_id_candidate) == true );
        REQUIRE( GetObjectValue_Command(the_session_id2, the_object_id_candidate, object_bytestring) == true );
        REQUIRE( object_bytestring.length == 24 );
        rnd_string(object_bytestring, result_string2);
        REQUIRE( result_string2.compare(result_string1) != 0 );
    }
}

TEST_CASE("Archive", "[Archive][Object]") {

    SECTION("Create Archive") {
        REQUIRE( CreateArchive_Command(the_session_id2, the_container_id1) == true );
    }

    SECTION("Create Archive in a closed Session") {
        REQUIRE( CreateArchive_Command(the_session_id4, the_container_id2) == false );
    }    

    SECTION("Add Objects to Archive") {
        archive_string ="The Quick Brown Fox";
        REQUIRE( Archive_Command(the_session_id2, the_container_id1, archive_string) == true );

        archive_string = " jumps over the lazy dog";
        REQUIRE( Archive_Command(the_session_id2, the_container_id1, archive_string) == true );
    }

    SECTION("Close Archive") {
        REQUIRE( CloseArchive_Command(the_session_id2, the_container_id1) == true );
    }
    
    SECTION("Close non existing Archive") {
        REQUIRE( CloseArchive_Command(the_session_id1, the_container_id1) == false );
    }

    SECTION("Add Object to a closed Archive") {
        archive_string = "Non existing Archive";
        REQUIRE( Archive_Command(the_session_id2, the_container_id1, archive_string) == false );
    }
}

TEST_CASE("Storage","[Storage][Object]") {
    // Storage files are stored in /tmp

    storage_name = "TheStorageFile";
    //storage_filename = "";

    SECTION("Create Storage") {
        REQUIRE(  CreateStorage_Command(the_session_id1, storage_name, the_container_id1) == true  );
        TDS::TD_Session * _session_1 = TDS::TD_Connection::get_connection()->get_session_manager()->get_session_by_id(the_session_id1);
        TDS::TD_Container * _container_1 =  (reinterpret_cast<TDS::TD_Container *>(_session_1->get_object_by_id(the_container_id1)));
        storage_filename = _container_1->get_storage_filename();
    }    

    SECTION("Check Storage File") {
        REQUIRE(  boost::filesystem::exists(storage_filename) == true  );
    }    

    SECTION("Check Storage File Size") {
        storage_size1 = boost::filesystem::file_size(storage_filename);
        REQUIRE(  storage_size1 > 0  );
    }       

    SECTION("Create Storage in a closed Session") {
        storage_name = "TheBadStorageFile.txt";
        REQUIRE( CreateStorage_Command(the_session_id4, storage_name, the_container_id2) == false  );
    }       

    SECTION("Store data") {
        storage_string = "The Quick Brown Fox";
        REQUIRE( StoreData_Command(the_session_id1, the_container_id1, storage_string, the_object_id11) == true );
        storage_size1 = boost::filesystem::file_size(storage_filename);
        REQUIRE( storage_size1 > 0);

        storage_string = " jumps over the lazy dog";
        REQUIRE( StoreData_Command(the_session_id1, the_container_id1, storage_string, the_object_id21) == true );
        storage_size2 = boost::filesystem::file_size(storage_filename);
        REQUIRE( storage_size2 > storage_size1);
    }

    SECTION("Store empty data") {
        storage_string = "";
        REQUIRE( StoreData_Command(the_session_id1, the_container_id1, storage_string, the_object_id) == true );
    }

    SECTION("Store data to a wrong container") {
        storage_string ="Faulty text";
        REQUIRE( StoreData_Command(the_session_id1, the_object_id11, storage_string, the_object_id) == false );
    }
 
    SECTION("Get  Storage") {
        storage_name = "TheStorageFile.txt";
//        REQUIRE( GetStorage_Command(the_session_id1, storage_name, the_container_id2) == true );
    }  

    SECTION("Get wrong Storage") {
        storage_name = "FaultyStorage";
        REQUIRE( GetStorage_Command(the_session_id1, storage_name, the_container_id2) == false );
        REQUIRE( the_container_id2 == nil_uuid() );
    }  

    SECTION("Get Storage Value") {
        REQUIRE( GetStorageValue_Command(the_session_id1, the_container_id1, the_object_id21, object_bytestring) == true );
        bs_string(object_bytestring, object_value_string);
        REQUIRE( object_value_string.length() == std::string(" jumps over the lazy dog").length() );
    }       

    SECTION("Get Storage Value in wrong session") {
        REQUIRE( GetStorageValue_Command(the_session_id2, the_container_id1, the_object_id21, object_bytestring) == false );
    }

    SECTION("Get Storage Value in wrong container") {
        REQUIRE( GetStorageValue_Command(the_session_id1, the_container_id2, the_object_id21, object_bytestring) == false );
    }     

    SECTION("Get Storage Value for wrong object_id") {
        REQUIRE( GetStorageValue_Command(the_session_id1, the_container_id2, the_object_id11, object_bytestring) == false );
    }

    SECTION("Delete Storage in wrong session") {
        REQUIRE( DeleteStorage_Command(the_session_id2, the_container_id1) == false);
    }

    SECTION("Delete Storage") {
        REQUIRE( DeleteStorage_Command(the_session_id1, the_container_id1) == true);
    }

    SECTION("Delete non existing Storage") {
        REQUIRE( DeleteStorage_Command(the_session_id1, the_container_id1) == false);
    }

    SECTION("Store data in closed Storage") {
        storage_string ="Faulty text";
        REQUIRE( StoreData_Command(the_session_id1, the_container_id1, storage_string, the_object_id) == false );
    }

    SECTION("Get Storage Value in closed Storage") {
        REQUIRE( GetStorageValue_Command(the_session_id1, the_container_id1, the_object_id21, object_bytestring) == false );
    }        
}

TEST_CASE("Zero", "[Object][Session][Archive][Storage]") {
    REQUIRE( PutObjectValue_Command(the_session_id1, nil_uuid(), object_bytestring) == false );
    REQUIRE( GetObjectValue_Command(the_session_id1, nil_uuid(), object_bytestring) == false );

    REQUIRE( GetRandom_Command(the_session_id1, 0, the_object_id_reference) == true );

    CreateArchive_Command(the_session_id1, the_container_id1);
    the_container_id1 = nil_uuid();
    REQUIRE( Archive_Command(the_session_id2, the_container_id1, archive_string) == false ); 

    storage_name = "TheStorageFile.txt";
    CreateStorage_Command(the_session_id1, storage_name, the_container_id1);
    storage_string = "The Quick Brown Fox";
    the_container_id1 = nil_uuid();
    REQUIRE( StoreData_Command(the_session_id1, the_container_id1, storage_string, the_object_id11) == false );
    REQUIRE( GetStorageValue_Command(the_session_id1, the_container_id1, the_object_id21, object_bytestring) == false );
    REQUIRE( DeleteStorage_Command(the_session_id1, the_container_id1) == false);
}
