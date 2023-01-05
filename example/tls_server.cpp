/*
* TLS echo server using BSD sockets
* (C) 2014 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include "sandbox.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM) && \
   defined(BOTAN_TARGET_OS_HAS_SOCKETS)

#if defined(SO_USER_COOKIE)
#define SOCKET_ID 1
#else
#define SOCKET_ID 0
#endif

#include <botan/tls_server.h>
#include <botan/tls_policy.h>
#include <botan/hex.h>
#include <botan/internal/os_utils.h>
#include <botan/mem_ops.h>

#include <list>
#include <fstream>
#include <iomanip> 
#include <vector>

#include "tls_helpers.h"
#include "socket_utils.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/base_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include "TDS_CType.h"
#include "TDS_Constants.h"
#include "TDS_Commands.h"
#include "TDS_Connection.h"
#include "TDS_TTLV_Tools.h"
#include "TDS_Connection.h"
#include "TDS_TTLV_Tools.h"

#include "TDS_Connection_Commands.h" 
#include "TDS_Session_Commands.h"
#include "TDS_Object_Commands.h"
#include "TDS_Archive_Commands.h"
#include "TDS_Storage_Commands.h"
#include "TDS_Crypto_Commands.h"


#define __STDC_FORMAT_MACROS // non needed in C, only in C++
#include <inttypes.h>
#include <stdio.h>


auto logger = spdlog::stdout_color_mt("tls_server");

namespace Botan_CLI {

class TLS_Server final : public Command, public Botan::TLS::Callbacks {
   public:
      
      TLS_Server() : Command("tls_server cert key --port=443 --type=tcp --policy=default --dump-traces= --max-clients=0") {
         init_sockets();
      }

      ~TLS_Server() {
         stop_sockets();
      }

      std::string group() const override {
         return "tls";
      }

      std::string description() const override {
         return "Accept TLS/DTLS connections from TLS/DTLS clients";
      }

      void go() override {
         const std::string server_crt = get_arg("cert");
         const std::string server_key = get_arg("key");
         const uint16_t port = get_arg_u16("port");
         const size_t max_clients = get_arg_sz("max-clients");
         const std::string transport = get_arg("type");
         const std::string dump_traces_to = get_arg("dump-traces");

         if(transport != "tcp" && transport != "udp") {
            throw CLI_Usage_Error("Invalid transport type '" + transport + "' for TLS");
         }

         m_is_tcp = (transport == "tcp");

         auto policy = load_tls_policy(get_arg("policy"));

         Botan::TLS::Session_Manager_In_Memory session_manager(rng()); // TODO sqlite3

         Basic_Credentials_Manager creds(rng(), server_crt, server_key);

         logger->info("Listening for new connections on [{}] port [{}]", transport, port);

         if( !m_sandbox.init() ) {
            logger->critical("Failed sandboxing");
            return;
         }

         socket_type server_fd = make_server_socket(port);
         size_t clients_served = 0;

         while(true) {
            if( max_clients > 0 && clients_served >= max_clients ) break;

            if( m_is_tcp ) {
               m_socket = ::accept(server_fd, nullptr, nullptr);
            } else {
               struct sockaddr_in from;
               socklen_t from_len = sizeof(sockaddr_in);

               void* peek_buf = nullptr;
               size_t peek_len = 0;

               if( ::recvfrom(server_fd, static_cast<char*>(peek_buf), static_cast<sendrecv_len_type>(peek_len),
                             MSG_PEEK, reinterpret_cast<struct sockaddr*>(&from), &from_len) != 0 )  {
                  throw CLI_Error("Could not peek next packet");
               }

               if( ::connect(server_fd, reinterpret_cast<struct sockaddr*>(&from), from_len) != 0 ) {
                  throw CLI_Error("Could not connect UDP socket");
               }
               
               m_socket = server_fd;
            }

            clients_served++;

            Botan::TLS::Server server(
               *this,
               session_manager,
               creds,
               *policy,
               rng(),
               m_is_tcp == false);

            std::unique_ptr<std::ostream> dump_stream;

            if( !dump_traces_to.empty() ) {
               uint64_t timestamp = Botan::OS::get_high_resolution_clock();
               const std::string dump_file = dump_traces_to + "/tls_" + std::to_string(timestamp) + ".bin";
               dump_stream.reset(new std::ofstream(dump_file.c_str()));
            }

            memset(msg_buffer, 0x00, 4*1024);
            msg_offset = 0;
            msg_length = 0;

            try {
               while( !server.is_closed() ) {
                  try {
                     uint8_t buf[4 * 1024] = { 0 };
                     ssize_t got = ::recv(m_socket, Botan::cast_uint8_ptr_to_char(buf), sizeof(buf), 0);

                     if( got == -1 ) {
                        logger->error("Error in socket read - {}", err_to_string(errno));
                        break;
                     }

                     if( got == 0 ) {
                        logger->error("EOF received - Client disconnected");
                        break;
                     }

                     if( dump_stream ) {
                        dump_stream->write(reinterpret_cast<const char*>(buf), got);
                     }

                     server.received_data(buf, got);
                     //logger->debug("received [{}]", got);

                     while( server.is_active() && !m_pending_output.empty() ) {

                        output_entry output = m_pending_output.front();  
                        server.send(output.first, output.second);

                        m_pending_output.pop_front();
                        delete [] output.first;

                     }

                  } catch(std::exception& e) {
                     logger->warn("Connection problem: {}", e.what());
                     if( m_is_tcp ) {
                        close_socket(m_socket);
                        m_socket = invalid_socket();
                     }
                  }
               }
            } catch(Botan::Exception& e) {
               logger->error("Connection failed: {}", e.what());
            }

            if( m_is_tcp ) {
               close_socket(m_socket);
               m_socket = invalid_socket();
            }
         }

         close_socket(server_fd);
      }
   private:
      socket_type make_server_socket(uint16_t port) {
         const int type = m_is_tcp ? SOCK_STREAM : SOCK_DGRAM;

         socket_type fd = ::socket(PF_INET, type, 0);
         if( fd == invalid_socket() ) {
            throw CLI_Error("Unable to acquire socket");
         }

         sockaddr_in socket_info;
         Botan::clear_mem(&socket_info, 1);
         socket_info.sin_family = AF_INET;
         socket_info.sin_port = htons(port);

         // FIXME: support limiting listeners
         socket_info.sin_addr.s_addr = INADDR_ANY;

         if( ::bind(fd, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr)) != 0 ) {
            close_socket(fd);
            throw CLI_Error("server bind failed");
         }

         if( m_is_tcp ) {
            if( ::listen(fd, 100) != 0 ) {
               close_socket(fd);
               throw CLI_Error("listen failed");
            }
         }
         
         return fd;
      }

      bool tls_session_established(const Botan::TLS::Session& session) override {
         logger->info("Handshake complete, {} using {}", session.version().to_string(), session.ciphersuite().to_string());

         if( !session.session_id().empty() ) {
            logger->info("Session ID : {}", Botan::hex_encode(session.session_id()));
         }

         if( !session.session_ticket().empty() ) {
            logger->info("Session ticket : {}", Botan::hex_encode(session.session_ticket()));
         }

         return true;
      }

      void tls_record_received(uint64_t, const uint8_t input[], size_t input_len) override {    
         std::vector<uint8_t> vec(input, input + input_len);
         //logger->debug("tls_record_received : [{}] [{:n} ] [{}:{}]", input_len, spdlog::to_hex(std::begin(vec), std::begin(vec) + input_len), msg_length, msg_offset);

         if( msg_length == 0 && msg_offset == 0 ) {
            if( input_len > 7 ) {
               memcpy(&msg_length, input, sizeof(uint64_t));
               logger->debug("Retrieving message length: [{}]", msg_length);
            } else {
               // Well ... something very wrong happened ...
               logger->error("Well well well....");
            }
         } else {

            for( size_t i = 0; i != input_len; ++i ) {
               msg_buffer[msg_offset++] = reinterpret_cast<uint8_t>(input[i]);
            }
         }

         if( msg_length == msg_offset) {
            logger->debug("Message Fully Retrieved : {} out of {}", msg_offset, msg_length);
            execute_command_from_msg(msg_offset);
            msg_length = 0;
            msg_offset = 0;
            memset(msg_buffer, 0x00, 4*1024);
         }
      }

      void tls_emit_data(const uint8_t buf[], size_t length) override {
         //logger->debug("tls_emit_data [{}]", length);
         std::vector<uint8_t> vec(buf, buf + length);
         //logger->debug("tls_emit_data : [{}] [{:n} ]", length, spdlog::to_hex(std::begin(vec), std::begin(vec) + length));

         if( m_is_tcp ) {
            ssize_t sent = ::send(m_socket, buf, static_cast<sendrecv_len_type>(length), MSG_NOSIGNAL);

            if( sent == -1 ) {
               logger->error("Error writing to socket - {}", err_to_string(errno));
            } else if( sent != static_cast<ssize_t>(length) ) {
               logger->error("Packet of length {} truncated to {}", length, sent);
            }
         } else {
            while( length ) {
               ssize_t sent = ::send(m_socket, buf, static_cast<sendrecv_len_type>(length), MSG_NOSIGNAL);

               if( sent == -1 ) {
                  if( errno == EINTR ) {
                     sent = 0;
                  } else {
                     throw CLI_Error("Socket write failed");
                  }
               }

               buf += sent;
               length -= sent;
            }
         }
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         logger->warn("Alert: {}", alert.type_string());
      }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>&) override {
         // we ignore whatever the client sends here
         return "echo/0.1";
      }


      /***********************************************************************************************
       * TLS 103457 SPECIFIC
       * *********************************************************************************************/

      void add_command_code_response(TDS::TDSC_COMMAND_TYPE_t cmd_type) {
         TDS::TDSC_COMMAND_TYPE_t * return_code = new TDS::TDSC_COMMAND_TYPE_t;
         memcpy(return_code, &cmd_type, sizeof(TDS::TDSC_COMMAND_TYPE_t));
         output_entry entry = std::make_pair(reinterpret_cast<uint8_t *>(return_code), sizeof(TDS::TDSC_COMMAND_TYPE_t));
         m_pending_output.push_back(entry);  
      }
      
      void add_status_code_response(TDS::TDSC_STATUS_CODE_t status_code) {
         TDS::TDSC_STATUS_CODE_t * return_code = new TDS::TDSC_STATUS_CODE_t;
         memcpy(return_code, &status_code, sizeof(TDS::TDSC_STATUS_CODE_t));
         output_entry entry = std::make_pair(reinterpret_cast<uint8_t *>(return_code), sizeof(TDS::TDSC_STATUS_CODE_t));
         m_pending_output.push_back(entry);  
      }      

      void add_response(TDS::TDSC_TAG_t tag_v, TDS::TDSC_TYPE_t type_v, const TDS::TDSC_DATA_t &data) {

         TDS::TDSC_TAG_t * tag_e = new TDS::TDSC_TAG_t;
         memcpy(tag_e, &tag_v, sizeof(TDS::TDSC_TAG_t));

         TDS::TDSC_TYPE_t * type_e = new TDS::TDSC_TYPE_t;
         memcpy(type_e, &type_v, sizeof(TDS::TDSC_TYPE_t));

         TDS::TDSC_LENGTH_t * length_e = new TDS::TDSC_LENGTH_t;
         memcpy(length_e, &data.length, sizeof(TDS::TDSC_LENGTH_t));

         uint8_t * data_e = new uint8_t[data.length];
         memcpy(data_e, reinterpret_cast<const uint8_t*>(data.data) , data.length);

         output_entry e_tag    = std::make_pair(reinterpret_cast<uint8_t *>(tag_e), sizeof(TDS::TDSC_TAG_t));
         output_entry e_type   = std::make_pair(reinterpret_cast<uint8_t *>(type_e), sizeof(TDS::TDSC_TYPE_t));
         output_entry e_length = std::make_pair(reinterpret_cast<uint8_t *>(length_e), sizeof(TDS::TDSC_LENGTH_t));
         output_entry entry    = std::make_pair(data_e, data.length*sizeof(uint8_t));

         m_pending_output.push_back(e_tag);
         m_pending_output.push_back(e_type);
         m_pending_output.push_back(e_length);
         m_pending_output.push_back(entry);
      }    

      void add_data_response(const TDS::TDSC_DATA_t &data) {
         add_response(TD_TTLV_TAG_DATA, TD_TTLV_TYPE_BYTESTRING, data);
      }  

      void add_session_id_response(const TDS::TDSC_SESSION_ID_t &session_id) {

         TDS::TDSC_DATA_t session_data;
         session_data.length = to_string(session_id).length();
         session_data.data = new char[session_data.length+1];
         memcpy(session_data.data, to_string(session_id).c_str() , session_data.length);

         add_response(TD_TTLV_TAG_SESSIONID, TD_TTLV_TYPE_BYTESTRING, session_data);
      }

      void add_object_id_response(const TDS::TDSC_OBJECT_ID_t &object_id) {

         TDS::TDSC_DATA_t object_data;
         object_data.length = to_string(object_id).length();
         object_data.data = new char[object_data.length+1];
         memcpy(object_data.data, to_string(object_id).c_str() , object_data.length);

         add_response(TD_TTLV_TAG_OBJECTID, TD_TTLV_TYPE_BYTESTRING, object_data);   
      } 

      void add_container_id_response(const TDS::TDSC_CONTAINER_ID_t &container_id) {
 
         TDS::TDSC_DATA_t container_data;
         container_data.length = to_string(container_id).length();
         container_data.data = new char[container_data.length+1];
         memcpy(container_data.data, to_string(container_id).c_str() , container_data.length);

         add_response(TD_TTLV_TAG_CONTAINERID , TD_TTLV_TYPE_BYTESTRING, container_data); 
      }

      TDS::TDSC_STATUS_CODE_t execute_command_from_msg(uint64_t msgl) {
         TDS::TDSC_STATUS_CODE_t returnCode = TDS::TDSC_GENERAL_FAILURE;
         uint8_t cmd_type = msg_buffer[0];

         std::vector<uint8_t> vec(msg_buffer, msg_buffer + msgl);
         logger->debug("execute_command_from_msg : [{}]\n[{:n} ]", msgl, spdlog::to_hex(std::begin(vec), std::begin(vec) + msgl));

         switch( cmd_type ) {
         
            case TD_OPENCONNECTION_CMD :  
                        {
                           logger->info("TD_OPENCONNECTION_CMD");
                           std::unique_ptr<TDS::TD_OpenConnection_Command> the_command(new TDS::TD_OpenConnection_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_OPENCONNECTION_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_CONTAINER_ID_t the_container_id;
                              the_command->get_container_id(the_container_id);
                              logger->info("Container Id: [{}]", to_string(the_container_id));
                              add_container_id_response(the_container_id);
                           }                           
                        }
                        break;

            case TD_CLOSESESSION_CMD :  
                        {
                           logger->info("TD_CLOSESESSION_CMD");
                           std::unique_ptr<TDS::TD_CloseSession_Command> the_command(new TDS::TD_CloseSession_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);
                           
                           add_command_code_response(TD_CLOSESESSION_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_CREATESESSION_CMD :  
                        {
                           logger->info("TD_CREATESESSION_CMD");
                           std::unique_ptr<TDS::TD_CreateSession_Command> the_command(new TDS::TD_CreateSession_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_CREATESESSION_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              logger->info("Session Id: [{}]", to_string(the_command->get_session_id()));
                              add_session_id_response(the_command->get_session_id());
                           }
                        }
                        break;

            case TD_CLOSECONNECTION_CMD :  
                        {
                           logger->info("TD_CLOSECONNECTION_CMD");
                           std::unique_ptr<TDS::TD_CloseConnection_Command> the_command(new TDS::TD_CloseConnection_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);
                        }
                        break;                          

            case TD_CREATEOBJECT_CMD :  
                        {
                           logger->info("TD_CREATEOBJECT_CMD");
                           std::unique_ptr<TDS::TD_CreateObject_Command> the_command(new TDS::TD_CreateObject_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_CREATEOBJECT_RSP);
                           add_status_code_response(status_code);
                           
                           if( status_code == 0 ) {
                              TDS::TDSC_OBJECT_ID_t the_object_id;
                              the_command->get_object_id(the_object_id);
                              logger->info("Object Id : [{}]", to_string(the_object_id));
                              add_object_id_response(the_object_id);
                           }
                        }
                        break;

            case TD_PUTOBJECTVALUE_CMD :  
                        {
                           logger->info("TD_PUTOBJECTVALUE_CMD");
                           std::unique_ptr<TDS::TD_PutObjectValue_Command> the_command(new TDS::TD_PutObjectValue_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_PUTOBJECTVALUE_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_GETOBJECTVALUE_CMD :  
                        {
                           logger->info("TD_GETOBJECTVALUE_CMD");
                           std::unique_ptr<TDS::TD_GetObjectValue_Command> the_command(new TDS::TD_GetObjectValue_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GETOBJECTVALUE_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_DATA_t the_object_value;
                              the_command->get_object_value(the_object_value);
                              logger->info("Object Value Length : [{}]", the_object_value.length);
                              add_data_response(the_object_value);
                           }
                        }
                        break;

            case TD_CREATEARCHIVE_CMD :  
                        {
                           logger->info("TD_CREATEARCHIVE_CMD");
                           std::unique_ptr<TDS::TD_CreateArchive_Command> the_command(new TDS::TD_CreateArchive_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_CREATEARCHIVE_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_CONTAINER_ID_t the_container_id;
                              the_command->get_container_id(the_container_id);
                              logger->info("Container Id: [{}]", to_string(the_container_id));
                              add_container_id_response(the_container_id);
                           }
                        }
                        break;

            case TD_ARCHIVE_CMD :  
                        {
                           logger->info("TD_ARCHIVE_CMD");
                           std::unique_ptr<TDS::TD_Archive_Command> the_command(new TDS::TD_Archive_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_ARCHIVE_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_CLOSEARCHIVE_CMD :  
                        {
                           logger->info("TD_CLOSEARCHIVE_CMD");
                           std::unique_ptr<TDS::TD_CloseArchive_Command> the_command(new TDS::TD_CloseArchive_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_CLOSEARCHIVE_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_CREATESTORAGE_CMD :  
                        {
                           logger->info("TD_CREATESTORAGE_CMD");
                           std::unique_ptr<TDS::TD_CreateStorage_Command> the_command(new TDS::TD_CreateStorage_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_CREATESTORAGE_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_CONTAINER_ID_t the_container_id;
                              the_command->get_container_id(the_container_id);
                              logger->info("Container Id: [{}]", to_string(the_container_id));
                              add_container_id_response(the_container_id);
                           }
                        }
                        break;

            case TD_DELETESTORAGE_CMD :  
                        {
                           logger->info("TD_DELETESTORAGE_CMD");
                           std::unique_ptr<TDS::TD_DeleteStorage_Command> the_command(new TDS::TD_DeleteStorage_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_DELETESTORAGE_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_STOREDATA_CMD :  
                        {
                           logger->info("TD_STOREDATA_CMD");
                           std::unique_ptr<TDS::TD_StoreData_Command> the_command(new TDS::TD_StoreData_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_STOREDATA_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_OBJECT_ID_t the_object_id;
                              the_command->get_object_id(the_object_id);
                              logger->info("Object Id: [{}]", to_string(the_object_id));
                              add_object_id_response(the_object_id);
                           }
                        }
                        break;

            case TD_GETSTORAGEVALUE_CMD :  
                        {
                           logger->info("TD_GETSTORAGEVALUE_CMD");
                           std::unique_ptr<TDS::TD_GetStorageValue_Command> the_command(new TDS::TD_GetStorageValue_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GETSTORAGEVALUE_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_DATA_t the_object_value;
                              the_command->get_data(the_object_value);
                              logger->info("Object Value Length : [{}]", the_object_value.length);
                              add_data_response(the_object_value);
                           }
                        }
                        break;

            case TD_GETSTORAGE_CMD :  
                        {
                           logger->info("TD_GETSTORAGE_CMD");
                           std::unique_ptr<TDS::TD_GetStorage_Command> the_command(new TDS::TD_GetStorage_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GETSTORAGE_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_CONTAINER_ID_t the_container_id;
                              the_command->get_container_id(the_container_id);
                              logger->info("Container Id: [{}]", to_string(the_container_id));
                              add_container_id_response(the_container_id);
                           }
                        }
                        break;

            case TD_SEARCH_CMD : 
                        {
                           logger->info("TD_SEARCH_CMD");
                           std::unique_ptr<TDS::TD_Search_Command> the_command(new TDS::TD_Search_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_SEARCH_RSP);
                           add_status_code_response(status_code);
                           
                           if( status_code == 0 ) {
                              TDS::TDSC_OBJECT_ID_t the_object_id;
                              the_command->get_object_id(the_object_id);
                              logger->info("Object Id: [{}]", to_string(the_object_id));
                              add_object_id_response(the_object_id);
                           }                           
                        }
                        break;                        

            case TD_GETRANDOM_CMD :  
                        {
                           logger->info("TD_GETRANDOM_CMD");
                           std::unique_ptr<TDS::TD_GetRandom_Command> the_command(new TDS::TD_GetRandom_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GETRANDOM_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_OBJECT_ID_t the_object_id;
                              the_command->get_object_id(the_object_id);
                              logger->info("Object Id: [{}]", to_string(the_object_id));
                              add_object_id_response(the_object_id);
                           }
                        }
                        break;

            case TD_GENERATEENCRYPTIONKEY_CMD :  
                        {
                           logger->info("TD_GENERATEENCRYPTIONKEY_CMD");
                           std::unique_ptr<TDS::TD_GenerateEncryptionKey_Command> the_command(new TDS::TD_GenerateEncryptionKey_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GENERATEENCRYPTIONKEY_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_OBJECT_ID_t the_object_id;
                              the_command->get_object_id(the_object_id);
                              logger->info("Object Id: [{}]", to_string(the_object_id));
                              add_object_id_response(the_object_id);
                           }
                        }
                        break;

            case TD_GETTRUSTEDTIMESTAMP_CMD :  
                        {
                           logger->info("TD_GETTRUSTEDTIMESTAMP_CMD");
                           std::unique_ptr<TDS::TD_GetTrustedTimeStamping_Command> the_command(new TDS::TD_GetTrustedTimeStamping_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GETTRUSTEDTIMESTAMP_RSP);
                           add_status_code_response(status_code);

                           if( status_code == 0 ) {
                              TDS::TDSC_OBJECT_ID_t the_object_id;
                              the_command->get_object_id(the_object_id);
                              logger->info("Object Id: [{}]", to_string(the_object_id));
                              add_object_id_response(the_object_id);
                           }                           
                        }
                        break;

            case TD_TRUSTRENEWAL_CMD :  
                        {
                           logger->info("TD_TRUSTRENEWAL_CMD");
                           std::unique_ptr<TDS::TD_TrustRenewal_Command> the_command(new TDS::TD_TrustRenewal_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_TRUSTRENEWAL_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_GETVALUE_CMD :  
                        {
                           logger->info("TD_GETVALUE_CMD");
                           std::unique_ptr<TDS::TD_GetValue_Command> the_command(new TDS::TD_GetValue_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           logger->info("execute_command status_code: [{}]", status_code);

                           add_command_code_response(TD_GETVALUE_RSP);
                           add_status_code_response(status_code);
                        }
                        break;

            case TD_DUMPCONNECTION_CMD :  
                        {
                           logger->info("DUMP CONNECTION REQUESTED");
                           TDS::TD_Connection::get_connection()->dump_connection();
                        }
                        break;       

            case APP_KILLSWITCH_CMD : 
                        {
                           logger->critical("APP_KILLSWITCH_CMD");
                           // Closing connection
                           std::unique_ptr<TDS::TD_CloseConnection_Command> the_command(new TDS::TD_CloseConnection_Command());
                           the_command->set_command_type(cmd_type);
                           TDS::TD_Message * the_message = new TDS::TD_Message(reinterpret_cast<char*>(msg_buffer), msg_length);
                           the_command->set_message(the_message);
                           TDS::TDSC_STATUS_CODE_t status_code = the_command->execute_command();
                           //TDS::TDSC_STATUS_CODE_t status_code = 0;
                           logger->info("execute_command status_code: [{}]", status_code);

                           exit(0); 
                        }
                        break; 
         }

         return returnCode;
      }

      socket_type m_socket = invalid_socket();
      bool m_is_tcp = false;
      uint32_t m_socket_id = 0;
      std::string m_line_buf;

      typedef pair<uint8_t *,uint8_t>  output_entry;
      std::list<output_entry> m_pending_output;

      Sandbox m_sandbox;

      uint8_t msg_buffer[4*1024];
      uint8_t msg_offset = 0;
      uint64_t msg_length = 0L;

   };

BOTAN_REGISTER_COMMAND("tls_server", TLS_Server);

}

#endif
