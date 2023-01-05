#!/usr/bin/python3

import tkinter as tk
import pygubu
import argparse
from tkinter import messagebox
from tkinter import scrolledtext
import logging
import time
import binascii
import socket
import struct
import sys
import socket
import ssl
import threading
import uuid

import tds_constants


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler('logfile.log')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.DEBUG)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)
logger.propagate = False

encryption_type = {'RSA1024':30, 'RSA2048':31, 'RSA4096':32, 'AES-128':33, 'AES-256':34}
trust_timer = 240

logger.info('Starting ETSI103457 python client sample')


# Server certificate creation
# openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt
#
# Client certificate creation
# openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout client.key -out client.crt


server_sni_hostname = 'etsi103457.sample'
nil_uuid = '00000000-0000-0000-0000-000000000000'

class ETSI103457App():

    is_connected = False
    
    def __init__(self):

        #1: Create a builder
        self.builder = pygubu.Builder()

        #2: Load an ui file
        self.builder.add_from_file('etsi103457.ui')

        #3: Create the mainwindow
        self.mainwindow = self.builder.get_object('Toplevel')
        self.mainwindow.title('ETSI103457 Client Sample')

        self.mainwindow.protocol("WM_DELETE_WINDOW", self.on_close_window)

        self.builder.connect_callbacks(self)

        self.logbox = scrolledtext.ScrolledText(self.builder.get_object('Response_Frame'), width=160, height=30, wrap=tk.CHAR, background='#e2f0d9', takefocus=False)
        self.logbox.grid(column=0, row=0, sticky='nsew')

        callbacks = {
            'on_OpenConnection_Button_clicked': self.on_OpenConnection_Button_clicked,
            'on_CloseConnection_Button_clicked': self.on_CloseConnection_Button_clicked,
            'on_Dump_Button_clicked': self.on_Dump_Button_clicked,
            'on_ServerKillSwitch_Button_clicked': self.on_ServerKillSwitch_Button_clicked,

            'on_CreateSession_Button_clicked': self.on_CreateSession_Button_clicked,
            'on_CloseSession_Button_clicked': self.on_CloseSession_Button_clicked,

            'on_CreateObject_Button_clicked': self.on_CreateObject_Button_clicked,
            'on_PutObjectValue_Button_clicked': self.on_PutObjectValue_Button_clicked,
            'on_GetObjectValue_Button_clicked': self.on_GetObjectValue_Button_clicked,

            'on_CreateArchive_Button_clicked': self.on_CreateArchive_Button_clicked,
            'on_CloseArchive_Button_clicked': self.on_CloseArchive_Button_clicked,
            'on_Archive_Button_clicked': self.on_Archive_Button_clicked,
            
            'on_CreateStorage_Button_clicked': self.on_CreateStorage_Button_clicked,
            'on_DeleteStorage_Button_clicked': self.on_DeleteStorage_Button_clicked,
            'on_StoreData_Button_clicked': self.on_StoreData_Button_clicked,
            'on_GetStorageValue_Button_clicked': self.on_GetStorageValue_Button_clicked,
            'on_Search_Button_clicked': self.on_Search_Button_clicked,
            'on_GetStorage_Button_clicked': self.on_GetStorage_Button_clicked,

            'on_GetTrustedTimestamp_Button_clicked': self.on_GetTrustedTimestamp_Button_clicked,
            'on_GetRandom_Button_clicked': self.on_GetRandom_Button_clicked,
            'on_GenerateEncryptionKey_Button_clicked': self.on_GenerateEncryptionKey_Button_clicked
            }
        
        self.builder.connect_callbacks(callbacks)

        self.set_connection_frame('normal')
        self.set_active_session_frame('disabled')
        self.set_session_frame('disabled')
        self.set_object_frame('disabled')
        self.set_archive_frame('disabled')
        self.set_storage_frame('disabled')
        self.set_crypto_frame('disabled')

        self.ip_vars = tk.StringVar()
        self.ip_vars.set('XXX.XXX.XXX.XXX') 
        self.ip_vars.set('127.0.0.1') 
        self.ip_vars.trace('w', self.validate_ip_format)
        self.builder.get_object('Server_IP_Entry').config(textvariable=self.ip_vars)

        self.ip_port_vars = tk.StringVar()
        self.ip_port_vars.set('XXXXX') 
        self.ip_port_vars.set('4027') 
        self.ip_port_vars.trace('w', self.validate_ip_port)
        self.builder.get_object('Server_Port_Entry').config(textvariable=self.ip_port_vars)

        self.random_length_vars = tk.StringVar()
        self.random_length_vars.set('Length')     
        self.random_length_vars.trace('w', self.validate_random_length)
        self.builder.get_object('GetRandom_Entry').config(textvariable=self.random_length_vars)

        self.trusted_vars = tk.IntVar()
        self.builder.get_object('Trusted_Checkbutton').select()

        self.logbox.tag_configure('info', foreground='blue')
        self.logbox.tag_configure('success', foreground='green')
        self.logbox.tag_configure('failure', foreground='red')
        self.logbox.tag_configure('trust', foreground='grey')

        self.builder.get_object('GenerateEncryptionKey_Entry').current(0)

        self.is_connected = False
        self.is_running = True
        self.lock = threading.Lock()
        self.trust_renew_function()

    def on_close_window(self):
        self.is_running = False
        self.timer_t.cancel()
        self.mainwindow.destroy()


    def log_message(self, msg):
        message = time.ctime() + ': ' + msg + '\n'

        if msg.startswith('[Trust'):
            self.logbox.insert(tk.END, str(message), 'trust')
        else:
            if msg.startswith('['):
                self.logbox.insert(tk.END, str(message), 'info')
            else:
                if msg.startswith('STATUS'):
                    if 'Success' in msg:
                        self.logbox.insert(tk.END, str(message), 'success')
                    else:
                        self.logbox.insert(tk.END, str(message), 'failure')
                else:
                    if msg.startswith('>'):
                        self.logbox.insert(tk.END, str(message))

        self.logbox.yview_pickplace(tk.END)
        logger.debug(msg)


    def encode_command(self, command_number):
        packed_data = struct.pack('B',command_number)
        return packed_data


    def encode_msg_length(self, msg_length):
        packed_data = struct.pack('Q',msg_length)
        return packed_data        


    def encode_binary(self, tag, ustring, type):
        unicode_string = bytes(ustring, 'utf-8')
        packed_data_tag = struct.pack('B', tag)
        packed_data_type = struct.pack('H', type)
        packed_data_length = struct.pack('Q', len(unicode_string))
        packed_data_value = struct.pack('{0}s'.format(len(unicode_string)), unicode_string)
        packed_data = packed_data_tag + packed_data_type + packed_data_length + packed_data_value
        return packed_data    

    def encode_unicode_string(self, tag, ustring):
        return self.encode_binary(tag, ustring, tds_constants.TD_TTLV_TYPE_UNICODESTRING)


    def encode_bytestring(self, tag, ustring):
        return self.encode_binary(tag, ustring, tds_constants.TD_TTLV_TYPE_BYTESTRING)


    def encode_uuid(self, tag, uuidstring):
        return self.encode_binary(tag, uuidstring, tds_constants.TD_TTLV_TYPE_UUID)


    def encode_integer(self, tag, value):
        packed_data_tag = struct.pack('B', tag)
        packed_data_type = struct.pack('H', tds_constants.TD_TTLV_TYPE_INTEGER)
        packed_data_length = struct.pack('Q', 8)
        packed_data_value = struct.pack('Q',value)
        packed_data = packed_data_tag + packed_data_type + packed_data_length + packed_data_value
        return packed_data


    def encode_symbol(self, tag, value):
        packed_data_tag = struct.pack('B', tag)
        packed_data_type = struct.pack('H', tds_constants.TD_TTLV_TYPE_SYMBOL)
        packed_data_length = struct.pack('Q', 1)
        packed_data_value = struct.pack('B',value)
        packed_data = packed_data_tag + packed_data_type + packed_data_length + packed_data_value
        return packed_data        


    def get_status_code(self):
        data = self.the_connection.recv(2)
        unpacked_status_code = struct.unpack('H', data)
        return unpacked_status_code[0]

    def get_cmd_type(self):
        data = self.the_connection.recv(1)
        unpacked_status_code = struct.unpack('B', data)
        return unpacked_status_code[0]


    def get_session_id(self):
        # TTLV format
        tag_t      = self.the_connection.recv(1)
        type_t     = self.the_connection.recv(2)
        length_t   = self.the_connection.recv(8)
        the_length = struct.unpack('Q', length_t)
        value_t    = self.the_connection.recv(the_length[0])
        return value_t       


    def get_object_id(self):
        # TTLV format
        tag_t      = self.the_connection.recv(1)
        type_t     = self.the_connection.recv(2)
        length_t   = self.the_connection.recv(8)
        the_length = struct.unpack('Q', length_t)
        value_t    = self.the_connection.recv(the_length[0])
        return value_t           


    def get_container_id(self):
        tag_t      = self.the_connection.recv(1)
        type_t     = self.the_connection.recv(2)
        length_t   = self.the_connection.recv(8)
        the_length = struct.unpack('Q', length_t)
        value_t    = self.the_connection.recv(the_length[0])
        return value_t           


    def get_bytestring(self):
        # TTLV format
        tag_t      = self.the_connection.recv(1)
        type_t     = self.the_connection.recv(2)
        length_t   = self.the_connection.recv(8)
        the_length = struct.unpack('Q', length_t)
        value_t    = self.the_connection.recv(the_length[0])
        return value_t


    def get_ui_as_uuid(self, ui_name):
        try:
            uuid_string = self.builder.get_object(ui_name).get()
            uuid_converted = uuid.UUID(uuid_string)
            uuid_value = uuid_string
        except:
            uuid_value = nil_uuid
        return uuid_value

        
    def on_OpenConnection_Button_clicked(self):
        self.log_message('[Connecting] to [' + self.builder.get_object('Server_IP_Entry').get() + '][' + self.builder.get_object('Server_Port_Entry').get() + ']')
        self.set_connection_frame('disabled')

        command_packed_data   = self.encode_command(tds_constants.TD_OPENCONNECTION_CMD)
        ltd_id_packed_data    = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_LTDID, self.builder.get_object('LTD_ID_Entry').get())
        ltd_role_packed_data  = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_LTDROLE, self.builder.get_object('LTD_Role_Entry').get())
        ltd_cn_packed_data    = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_CN, self.builder.get_object('LTD_CN_Entry').get())
        ltd_nonce_packed_data = self.encode_bytestring(tds_constants.TD_TTLV_TAG_NONCE, self.builder.get_object('LTD_Nonce_Entry').get())
        ltd_data_packed_data  = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('LTD_Data_Entry').get())

        msg_length = len(command_packed_data) + len(ltd_id_packed_data) + len(ltd_role_packed_data) \
                   + len(ltd_cn_packed_data) + len(ltd_nonce_packed_data) + len(ltd_data_packed_data)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
        self.context.load_cert_chain(certfile=client_cert, keyfile=client_key)

        self.the_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.the_connection = self.context.wrap_socket(self.the_socket, server_side=False, server_hostname=server_sni_hostname)

        try:
            self.the_connection.connect((self.builder.get_object('Server_IP_Entry').get(), int(self.builder.get_object('Server_Port_Entry').get())))
        except Exception as e:

            status_code = self.get_status_code()
            self.log_message('[on_OpenConnection Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.log_message('SSL Established. Peer: {}'.format(self.the_connection.getpeercert()))

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('LTD Id               [' + self.builder.get_object('LTD_ID_Entry').get() + ']: ' + str(binascii.hexlify(ltd_id_packed_data)))
        self.log_message('LTD Role             [' + self.builder.get_object('LTD_Role_Entry').get() + ']: ' + str(binascii.hexlify(ltd_role_packed_data)))
        self.log_message('LTD Certificate Name [' + self.builder.get_object('LTD_CN_Entry').get() + ']: ' + str(binascii.hexlify(ltd_cn_packed_data)))
        self.log_message('LTD Nonce            [' + self.builder.get_object('LTD_Nonce_Entry').get() + ']: ' + str(binascii.hexlify(ltd_nonce_packed_data)))
        self.log_message('LTD Data             [' + self.builder.get_object('LTD_Data_Entry').get() + ']: ' + str(binascii.hexlify(ltd_data_packed_data)))

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(ltd_id_packed_data)
            self.the_connection.sendall(ltd_role_packed_data)
            self.the_connection.sendall(ltd_cn_packed_data)
            self.the_connection.sendall(ltd_nonce_packed_data)
            self.the_connection.sendall(ltd_data_packed_data)
            
            cmd_type = self.get_cmd_type()
            status_code = self.get_status_code()

            if status_code == tds_constants.TDSC_SUCCESS:
                container_id = self.get_container_id()
                self.is_connected = True        

        except Exception as e:
            self.log_message('[on_OpenConnection Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_CloseConnection_Button_clicked(self):
        self.log_message('[CloseConnection] requested')
        self.lock.acquire(False)
        self.lock.release()

        self.set_connection_frame('normal')
        self.set_active_session_frame('disabled')
        self.set_session_frame('disabled')
        self.set_object_frame('disabled')
        self.set_archive_frame('disabled')
        self.set_storage_frame('disabled')
        self.set_crypto_frame('disabled')

        command_packed_data   = self.encode_command(tds_constants.TD_CLOSECONNECTION_CMD)
        msg_length = len(command_packed_data)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
        except Exception as e:
            self.log_message('[on_CloseConnection Connection error - resetting...][' + e.message + ']')

        self.lock.release()
        self.is_connected = False
        self.the_connection.close()


    def on_Dump_Button_clicked(self):
        self.log_message('[Dump Connection] requested')

        command_packed_data = self.encode_command(tds_constants.TD_DUMPCONNECTION_CMD)
        msg_length = len(command_packed_data) 
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
        except Exception as e:
            self.log_message('[on_Dump Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_CreateSession_Button_clicked(self):
        self.log_message('[CreateSession] requested') 

        self.set_close_session_frame('normal') 
        self.set_active_session_frame('normal')
        self.set_object_frame('normal')
        self.set_archive_frame('normal')
        self.set_storage_frame('normal')
        self.set_crypto_frame('normal')

        command_packed_data = self.encode_command(tds_constants.TD_CREATESESSION_CMD)
        msg_length = len(command_packed_data) 
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)

            cmd_type = self.get_cmd_type()
            status_code = self.get_status_code()

            if status_code == tds_constants.TDSC_SUCCESS:
                session_id = self.get_session_id()
                session_id_str = session_id.decode('utf-8')
                self.builder.get_object('ActiveSession_Entry').delete(0,tk.END)
                self.builder.get_object('ActiveSession_Entry').insert(0,session_id_str)

                self.builder.get_object('CloseSession_Entry').delete(0,tk.END)
                self.builder.get_object('CloseSession_Entry').insert(0,session_id_str)

                self.log_message('> Session Id: ' + session_id_str)

        except Exception as e:
            self.log_message('[on_Dump Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_CloseSession_Button_clicked(self):
        self.log_message('[CloseSession] requested')

        self.set_close_session_frame('disabled') 
        self.set_active_session_frame('disabled')
        self.set_object_frame('disabled')
        self.set_archive_frame('disabled')
        self.set_storage_frame('disabled')
        self.set_crypto_frame('disabled')        

        command_packed_data = self.encode_command(tds_constants.TD_CLOSESESSION_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('CloseSession_Entry'))
        
        msg_length = len(command_packed_data) + len(packed_session_id)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('CloseSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
    
        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

        except Exception as e:
            self.log_message('[on_CloseSession Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_CreateObject_Button_clicked(self):
        self.log_message('[CreateObject] requested')

        command_packed_data = self.encode_command(tds_constants.TD_CREATEOBJECT_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        
        msg_length = len(command_packed_data) + len(packed_session_id)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                object_id = self.get_object_id()
                object_id_str = object_id.decode('utf-8')
                
                self.builder.get_object('ActiveObject_Entry').delete(0,tk.END)
                self.builder.get_object('ActiveObject_Entry').insert(0,object_id_str)
                self.builder.get_object('GetObjectValue_Entry').delete(0,tk.END)
                self.builder.get_object('GetObjectValue_Entry').insert(0,object_id_str)
                
                self.log_message('> Object Id: ' + object_id_str)

        except Exception as e:
            self.log_message('[on_CreateObject Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_PutObjectValue_Button_clicked(self):
        self.log_message('[PutObjectValue] requested')

        command_packed_data = self.encode_command(tds_constants.TD_PUTOBJECTVALUE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_object_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_OBJECTID, self.get_ui_as_uuid('ActiveObject_Entry'))
            
        packed_object_value = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('PutObjectValue_Entry').get())
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_object_id) + len(packed_object_value)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Object Id            [' + self.builder.get_object('ActiveObject_Entry').get() + ']: ' + str(binascii.hexlify(packed_object_id)))
        self.log_message('Object Value         [' + self.builder.get_object('PutObjectValue_Entry').get() + ']: ' + str(binascii.hexlify(packed_object_value)))

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_object_id)
            self.the_connection.sendall(packed_object_value)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))
            
            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

        except Exception as e:
            self.log_message('[on_PutObjectValue Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()  
            return 

        self.lock.release()         

    def on_GetObjectValue_Button_clicked(self):
        self.log_message('[GetObjectValue] requested')

        command_packed_data = self.encode_command(tds_constants.TD_GETOBJECTVALUE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_object_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_OBJECTID, self.get_ui_as_uuid('GetObjectValue_Entry'))
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_object_id)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Object Id            [' + self.builder.get_object('GetObjectValue_Entry').get() + ']: ' + str(binascii.hexlify(packed_object_id)))

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_object_id)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                data = self.get_bytestring()
                self.log_message('> Data [' + str(data) + ']')

        except Exception as e:
            self.log_message('[on_GetObjectValue Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()    
            return

        self.lock.release()        


    def on_CreateArchive_Button_clicked(self):
        self.log_message('[CreateArchive] requested')  

        command_packed_data = self.encode_command(tds_constants.TD_CREATEARCHIVE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

        packed_container_type  = self.encode_symbol(tds_constants.TD_TTLV_TAG_CONTAINERTYPE, tds_constants.TDSC_CONTAINER_FILE) 
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_type)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' + str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Type       [' + 'FILE' + ']: ' + str(binascii.hexlify(packed_container_type))) 

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_type)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                container_id = self.get_container_id()
                container_id_str = container_id.decode('utf-8')

                self.builder.get_object('ActiveArchive_Entry').delete(0,tk.END)
                self.builder.get_object('ActiveArchive_Entry').insert(0,container_id_str)

                self.builder.get_object('CloseArchive_Entry').delete(0,tk.END)
                self.builder.get_object('CloseArchive_Entry').insert(0,container_id_str)

                self.log_message('> Container Id: ' + container_id_str)

        except Exception as e:
            self.log_message('[on_CreateArchive Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()  
            return

        self.lock.release()              


    def on_CloseArchive_Button_clicked(self):
        self.log_message('[CloseArchive] requested **')

        command_packed_data = self.encode_command(tds_constants.TD_CLOSEARCHIVE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_container_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_CONTAINERID, self.get_ui_as_uuid('CloseArchive_Entry'))

        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_id)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Id         [' + self.builder.get_object('CloseArchive_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_id))) 

        self.log_message('Message              [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)) +  str(binascii.hexlify(command_packed_data)) + str(binascii.hexlify(packed_session_id)) + str(binascii.hexlify(packed_container_id)))

        self.lock.acquire()

        self.log_message('Lock aquired')

        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_id)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))
        
        except Exception as e:
            self.log_message('[on_CloseArchive Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()  
            return

        self.lock.release()      
               

    def on_Archive_Button_clicked(self):
        self.log_message('[Archive_Button] requested')   

        command_packed_data = self.encode_command(tds_constants.TD_ARCHIVE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_container_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_CONTAINERID, self.get_ui_as_uuid('ActiveArchive_Entry'))
        packed_container_data  = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('Archive_Entry').get())   
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_id) + len(packed_container_data)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Id         [' + self.builder.get_object('ActiveArchive_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_id))) 
        self.log_message('Archive Data         [' + self.builder.get_object('Archive_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_data)))

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_id)
            self.the_connection.sendall(packed_container_data)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

        except Exception as e:
            self.log_message('[on_Archive Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_CreateStorage_Button_clicked(self):
        self.log_message('[CreateStorage] requested')   

        command_packed_data = self.encode_command(tds_constants.TD_CREATESTORAGE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

        packed_container_name  = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_CONTAINERNAME, self.builder.get_object('CreateStorage_Entry').get())   
        packed_container_type  = self.encode_symbol(tds_constants.TD_TTLV_TAG_CONTAINERTYPE, tds_constants.TDSC_CONTAINER_FILE) 
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_name) + len(packed_container_type)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Name       [' + self.builder.get_object('CreateStorage_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_name))) 
        self.log_message('Container Type       [' + 'FILE' + ']: ' + str(binascii.hexlify(packed_container_type))) 

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_name)
            self.the_connection.sendall(packed_container_type)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                container_id = self.get_container_id()
                container_id_str = container_id.decode('utf-8')
                
                self.builder.get_object('ActiveStorage_Entry').delete(0,tk.END)
                self.builder.get_object('ActiveStorage_Entry').insert(0,container_id_str)

                self.builder.get_object('DeleteStorage_Entry').delete(0,tk.END)
                self.builder.get_object('DeleteStorage_Entry').insert(0,container_id_str)

                self.log_message('> Container Id: ' + container_id_str)   

        except Exception as e:
            self.log_message('[on_CreateStorage Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked() 
            return  

        self.lock.release()                  


    def on_DeleteStorage_Button_clicked(self):
        self.log_message('[DeleteStorage] requested')   

        command_packed_data = self.encode_command(tds_constants.TD_DELETESTORAGE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_container_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_CONTAINERID, self.get_ui_as_uuid('DeleteStorage_Entry'))
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_id)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Id         [' + self.builder.get_object('DeleteStorage_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_id))) 

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_id)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

        except Exception as e:
            self.log_message('[on_DeleteStorage Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()  
            return

        self.lock.release()      
        

    def on_StoreData_Button_clicked(self):
        self.log_message('[StoreData] requested') 

        command_packed_data = self.encode_command(tds_constants.TD_STOREDATA_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_container_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_CONTAINERID, self.get_ui_as_uuid('ActiveStorage_Entry'))
        packed_container_data  = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('StoreData_Entry').get())  
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_id) + len(packed_container_data)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Id         [' + self.builder.get_object('ActiveStorage_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_id))) 
        self.log_message('Store Data           [' + self.builder.get_object('StoreData_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_data)))

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_id)
            self.the_connection.sendall(packed_container_data)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                object_id = self.get_object_id()
                object_id_str = object_id.decode('utf-8')
                self.log_message('> Object Id: ' + str(object_id))                
                self.builder.get_object('GetStorageValue_Entry').delete(0,tk.END)
                self.builder.get_object('GetStorageValue_Entry').insert(0,object_id_str)

        except Exception as e:
            self.log_message('[on_StoreData Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_GetStorageValue_Button_clicked(self):
        self.log_message('[GetStorageValue] requested')   

        command_packed_data = self.encode_command(tds_constants.TD_GETSTORAGEVALUE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_container_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_CONTAINERID, self.get_ui_as_uuid('ActiveStorage_Entry'))
        packed_object_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_OBJECTID, self.get_ui_as_uuid('GetStorageValue_Entry'))

        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_id) + len(packed_object_id)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Id         [' + self.builder.get_object('ActiveStorage_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_id))) 
        self.log_message('Object Id            [' + self.builder.get_object('GetStorageValue_Entry').get() + ']: ' + str(binascii.hexlify(packed_object_id)))   

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_id)
            self.the_connection.sendall(packed_object_id)
      
            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                data = self.get_bytestring()
                self.log_message('> Data [' + str(data) + ']')

        except Exception as e:
            self.log_message('[on_GetStorageValue Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_Search_Button_clicked(self):
        self.log_message('[Search] requested') 

        command_packed_data = self.encode_command(tds_constants.TD_SEARCH_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))
        packed_container_id  = self.encode_uuid(tds_constants.TD_TTLV_TAG_CONTAINERID, self.get_ui_as_uuid('ActiveStorage_Entry'))
        packed_object_value = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('Search_Entry').get())
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_id) + len(packed_object_value)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Id         [' + self.builder.get_object('ActiveStorage_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_id))) 
        self.log_message('Object Value         [' + self.builder.get_object('Search_Entry').get() + ']: ' + str(binascii.hexlify(packed_object_value)))   

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_id)
            self.the_connection.sendall(packed_object_value)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                object_id = self.get_object_id()
                self.log_message('> Object Id: ' + str(object_id))
        
        except Exception as e:
            self.log_message('[on_Search Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_GetStorage_Button_clicked(self):
        self.log_message('[GetStorage] requested')   

        command_packed_data = self.encode_command(tds_constants.TD_GETSTORAGE_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

        packed_container_name  = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_CONTAINERNAME, self.builder.get_object('GetStorage_Entry').get())  
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_container_name)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Container Name       [' + self.builder.get_object('GetStorage_Entry').get() + ']: ' + str(binascii.hexlify(packed_container_name))) 

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_container_name)
      
            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()

            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))
            if status_code == tds_constants.TDSC_SUCCESS:
                container_id = self.get_container_id()
                self.log_message('> Container Id: ' + str(container_id))

        except Exception as e:
            self.log_message('[on_GetStorage Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_GetTrustedTimestamp_Button_clicked(self):
        self.log_message('[GetTrustedTimestamp] requested')   

        command_packed_data = self.encode_command(tds_constants.TD_GETTRUSTEDTIMESTAMP_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

        packed_ts_data  = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('GetTrustedTimestamp_Entry').get())   
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_ts_data)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Data                 [' + self.builder.get_object('GetTrustedTimestamp_Entry').get() + ']: ' + str(binascii.hexlify(packed_ts_data)))   

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_ts_data)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))
            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                object_id = self.get_object_id()
                self.log_message('> Object Id: ' + str(object_id))

        except Exception as e:
            self.log_message('[on_GetTrustedTimestamp Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()
            return

        self.lock.release()


    def on_GetRandom_Button_clicked(self):
        self.log_message('[GetRandom] requested')   
        internal_error = False

        command_packed_data = self.encode_command(tds_constants.TD_GETRANDOM_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

        try:
            packed_size_in_bytes  = self.encode_integer(tds_constants.TD_TTLV_TAG_SIZEINBYTES, int(self.builder.get_object('GetRandom_Entry').get()))  
        except ValueError:
            packed_size_in_bytes  = self.encode_integer(tds_constants.TD_TTLV_TAG_SIZEINBYTES, 0)  
            internal_error = True
        
        if internal_error == False:
            msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_size_in_bytes)
            msg_length_packed_data = self.encode_msg_length(msg_length) 

            self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
            self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
            self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
            self.log_message('Size In Bytes        [' + self.builder.get_object('GetRandom_Entry').get() + ']: ' + str(binascii.hexlify(packed_size_in_bytes)))   

            self.lock.acquire()
            try:
                self.the_connection.sendall(msg_length_packed_data)
                self.the_connection.sendall(command_packed_data)
                self.the_connection.sendall(packed_session_id)
                self.the_connection.sendall(packed_size_in_bytes)

                cmd_type = self.get_cmd_type()
                self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

                status_code = self.get_status_code()
                self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

                if status_code == tds_constants.TDSC_SUCCESS:
                    object_id = self.get_object_id()
                    self.log_message('> Object Id: ' + str(object_id))

            except Exception as e:
                self.log_message('[on_GetRandom Connection error - resetting...][' + e.message + ']')
                self.on_CloseConnection_Button_clicked()  
                return

            self.lock.release()          
        else:
            self.log_message('[Incorrect Length]')

    def on_GenerateEncryptionKey_Button_clicked(self):
        self.log_message('[GenerateEncryptionKey] requested')   
        command_packed_data = self.encode_command(tds_constants.TD_GENERATEENCRYPTIONKEY_CMD)
        packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

        packed_key_type  = self.encode_symbol(tds_constants.TD_TTLV_TAG_KEYTYPE, int(encryption_type[self.builder.get_object('GenerateEncryptionKey_Entry').get()])) 
        
        msg_length = len(command_packed_data) + len(packed_session_id) + len(packed_key_type)
        msg_length_packed_data = self.encode_msg_length(msg_length) 

        self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
        self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
        self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
        self.log_message('Key Type             [' + str(encryption_type[self.builder.get_object('GenerateEncryptionKey_Entry').get()]) + ']: ' + str(binascii.hexlify(packed_key_type)))   

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
            self.the_connection.sendall(packed_session_id)
            self.the_connection.sendall(packed_key_type)

            cmd_type = self.get_cmd_type()
            self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

            status_code = self.get_status_code()
            self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            if status_code == tds_constants.TDSC_SUCCESS:
                object_id = self.get_object_id()
                self.log_message('> Object Id: ' + str(object_id))

        except Exception as e:
            self.log_message('[on_GenerateEncryptionKey Connection error - resetting...][' + e.message + ']')
            self.on_CloseConnection_Button_clicked()  
            return

        self.lock.release()          


    def on_ServerKillSwitch_Button_clicked(self):
        self.log_message('[ServerKillSwitch] activated') 

        self.set_connection_frame('normal')
        self.set_active_session_frame('disabled')
        self.set_session_frame('disabled')
        self.set_object_frame('disabled')
        self.set_archive_frame('disabled')
        self.set_storage_frame('disabled')
        self.set_crypto_frame('disabled')

        command_packed_data   = self.encode_command(tds_constants.APP_KILLSWITCH_CMD)
        msg_length = len(command_packed_data)
        msg_length_packed_data = self.encode_msg_length(msg_length)

        self.lock.acquire()
        try:
            self.the_connection.sendall(msg_length_packed_data)
            self.the_connection.sendall(command_packed_data)
        except:
            self.log_message('[Wait What ??...]')

        self.lock.release()
        self.is_connected = False
        self.the_connection.close()   


    def trust_renew_function(self):
        if self.is_connected:
            self.log_message('[Trust Renewal]')

            trusted = self.builder.get_variable('TrustedValue')
            trusted = trusted.get()

            command_packed_data = self.encode_command(tds_constants.TD_TRUSTRENEWAL_CMD)
            packed_session_id = self.encode_uuid(tds_constants.TD_TTLV_TAG_SESSIONID, self.get_ui_as_uuid('ActiveSession_Entry'))

            if trusted:
                ltd_cn_packed_data    = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_CN, self.builder.get_object('LTD_CN_Entry').get())
            else:
                ltd_cn_packed_data    = self.encode_unicode_string(tds_constants.TD_TTLV_TAG_CN, "BAD CN")
            ltd_nonce_packed_data = self.encode_bytestring(tds_constants.TD_TTLV_TAG_NONCE, self.builder.get_object('LTD_Nonce_Entry').get())
            ltd_data_packed_data  = self.encode_bytestring(tds_constants.TD_TTLV_TAG_DATA, self.builder.get_object('LTD_Data_Entry').get())

            msg_length = len(command_packed_data) + len(packed_session_id) + len(ltd_cn_packed_data) + len(ltd_nonce_packed_data) + len(ltd_data_packed_data)
            msg_length_packed_data = self.encode_msg_length(msg_length)

            self.log_message('Message Length       [' + str(msg_length) + ']: ' + str(binascii.hexlify(msg_length_packed_data)))
            self.log_message('Command              [' +  str(binascii.hexlify(command_packed_data)) + ']')
            self.log_message('Session Id           [' + self.builder.get_object('ActiveSession_Entry').get() + ']: ' + str(binascii.hexlify(packed_session_id)))
            self.log_message('LTD Certificate Name [' + self.builder.get_object('LTD_CN_Entry').get() + ']: ' + str(binascii.hexlify(ltd_cn_packed_data)))
            self.log_message('LTD Nonce            [' + self.builder.get_object('LTD_Nonce_Entry').get() + ']: ' + str(binascii.hexlify(ltd_nonce_packed_data)))
            self.log_message('LTD Data             [' + self.builder.get_object('LTD_Data_Entry').get() + ']: ' + str(binascii.hexlify(ltd_data_packed_data)))

            if trusted:
                self.log_message('Trusted              [' + str(trusted) + ']')
        
            self.lock.acquire()
            self.log_message('Lock acquired')

            try:
                self.the_connection.sendall(msg_length_packed_data)
                self.the_connection.sendall(command_packed_data)
                self.the_connection.sendall(packed_session_id)
                self.the_connection.sendall(ltd_cn_packed_data)
                self.the_connection.sendall(ltd_nonce_packed_data)
                self.the_connection.sendall(ltd_data_packed_data)

                self.log_message('Data sent... waiting for response')

                cmd_type = self.get_cmd_type()
                self.log_message('> Command type response received: ' + self.get_command_response_string(cmd_type))

                status_code = self.get_status_code()
                if status_code:
                    self.log_message('STATUS CODE [' + str(status_code) + ']: ' + self.get_status_code_string(status_code))

            except Exception as e:
                self.log_message('[trust_renew Connection error - resetting...][' + e.message + ']')
                self.on_CloseConnection_Button_clicked()  
                return

            self.lock.release()  

        if self.is_running:
            self.timer_t = threading.Timer(trust_timer, self.trust_renew_function)
            self.timer_t.start()        


    def set_serveur_frame(self,state):
        self.builder.get_object('Server_IP_Entry').config(state=state)
        self.builder.get_object('Server_Port_Entry').config(state=state)
        self.builder.get_object('LTD_ID_Entry').config(state=state)
        self.builder.get_object('LTD_Role_Entry').config(state=state)
        self.builder.get_object('LTD_CN_Entry').config(state=state)
        self.builder.get_object('LTD_Nonce_Entry').config(state=state)
        self.builder.get_object('LTD_Data_Entry').config(state=state)


    def set_connection_frame(self, state):
        if state == 'disabled':
            opposite = 'normal'
        else:
            opposite = 'disabled'

        self.set_serveur_frame(state)
        self.builder.get_object('OpenConnection_Button').config(state=state)
        self.builder.get_object('CloseConnection_Button').config(state=opposite)
        self.builder.get_object('Dump_Button').config(state=opposite)
        self.builder.get_object('CreateSession_Button').config(state=opposite)
        self.builder.get_object('ServerKillSwitch_Button').config(state=opposite)
        self.builder.get_object('Trusted_Checkbutton').select()
        self.builder.get_object('Trusted_Checkbutton').config(state=opposite) 


    def set_session_frame(self,state):
        self.builder.get_object('CreateSession_Button').config(state=state)
        self.builder.get_object('CloseSession_Button').config(state=state) 
        self.builder.get_object('CloseSession_Entry').config(state=state) 
        self.builder.get_object('Trusted_Checkbutton').config(state=state)           


    def set_close_session_frame(self,state):
        self.builder.get_object('CloseSession_Button').config(state=state) 
        self.builder.get_object('CloseSession_Entry').config(state=state)  
    

    def set_active_session_frame(self,state):
        self.builder.get_object('ActiveSession_Entry').config(state=state) 


    def set_object_frame(self,state):
        self.builder.get_object('CreateObject_Button').config(state=state)
        self.builder.get_object('ActiveObject_Entry').config(state=state)
        self.builder.get_object('PutObjectValue_Button').config(state=state)
        self.builder.get_object('PutObjectValue_Entry').config(state=state)
        self.builder.get_object('GetObjectValue_Button').config(state=state)
        self.builder.get_object('GetObjectValue_Entry').config(state=state)


    def set_archive_frame(self,state):
        self.builder.get_object('CreateArchive_Button').config(state=state)
        self.builder.get_object('CloseArchive_Button').config(state=state)
        self.builder.get_object('CloseArchive_Entry').config(state=state)
        self.builder.get_object('ActiveArchive_Entry').config(state=state)
        self.builder.get_object('Archive_Button').config(state=state)
        self.builder.get_object('Archive_Entry').config(state=state)  


    def set_storage_frame(self,state):
        self.builder.get_object('CreateStorage_Button').config(state=state)
        self.builder.get_object('CreateStorage_Entry').config(state=state)
        self.builder.get_object('DeleteStorage_Button').config(state=state)
        self.builder.get_object('DeleteStorage_Entry').config(state=state)
        self.builder.get_object('ActiveStorage_Entry').config(state=state)
        self.builder.get_object('StoreData_Button').config(state=state)
        self.builder.get_object('StoreData_Entry').config(state=state)
        self.builder.get_object('GetStorageValue_Button').config(state=state)
        self.builder.get_object('GetStorageValue_Entry').config(state=state)   
        self.builder.get_object('Search_Button').config(state=state)
        self.builder.get_object('Search_Entry').config(state=state)    
        self.builder.get_object('GetStorage_Button').config(state=state)
        self.builder.get_object('GetStorage_Entry').config(state=state)    


    def set_crypto_frame(self,state):
        self.builder.get_object('GetTrustedTimestamp_Button').config(state=state)
        self.builder.get_object('GetTrustedTimestamp_Entry').config(state=state)
        self.builder.get_object('GetRandom_Button').config(state=state)
        self.builder.get_object('GetRandom_Entry').config(state=state)
        self.builder.get_object('GenerateEncryptionKey_Button').config(state=state)

        if state == 'disabled':
            self.builder.get_object('GenerateEncryptionKey_Entry').config(state=state)
        else:
            self.builder.get_object('GenerateEncryptionKey_Entry').config(state='readonly')


    def validate_ip_format(self, *args):
        if not all([c.isdigit() or c == '.' for c in self.ip_vars.get()]):
            corrected = self.ip_vars.get()[:-1]
            self.ip_vars.set(corrected) 


    def validate_ip_port(self, *args):
        if not self.ip_port_vars.get().isnumeric():
            corrected = ''.join(filter(str.isnumeric, self.ip_port_vars.get()))
            self.ip_port_vars.set(corrected)  


    def validate_random_length(self, *args):
        if not self.random_length_vars.get().isnumeric():
            corrected = ''.join(filter(str.isnumeric, self.random_length_vars.get()))
            self.random_length_vars.set(corrected)   

    def get_command_response_string(self, cmd_type):
        switcher = {
            3   : 'TD_OPENCONNECTION_RSP',
            5   : 'TD_PUTOBJECTVALUE_RSP',
            7   : 'TD_CREATESESSION_RSP',
            9   : 'TD_CLOSESESSION_RSP',
            11  : 'TD_GETRANDOM_RSP',
            13  : 'TD_GENERATEENCRYPTIONKEY_RSP',
            15  : 'TD_CREATEARCHIVE_RSP',
            17  : 'TD_ARCHIVE_RSP',
            19  : 'TD_CLOSEARCHIVE_RSP',
            21  : 'TD_CREATESTORAGE_RSP',
            23  : 'TD_DELETESTORAGE_RSP',
            25  : 'TD_STOREDATA_RSP',
            27  : 'TD_GETVALUE_RSP',
            29  : 'TD_GETSTORAGEVALUE_RSP',
            31  : 'TD_GETSTORAGE_RSP',
            33  : 'TD_SEARCH_RSP',
            35  : 'TD_GETTRUSTEDTIMESTAMP_RSP',
            37  : 'TD_TRUSTRENEWAL_RSP',
            89  : 'TD_DUMPCONNECTION_RSP',
            91  : 'TD_CLOSECONNECTION_RSP',
            101 : 'TD_GETOBJECTVALUE_RSP',
            111 : 'TD_CREATEOBJECT_RSP',
        }
        return switcher.get(cmd_type,'Unknows RSP')


    def get_status_code_string(self, status_code):
        switcher = {
            0   : 'Success',
            1   : 'General failure',
            2   : 'Session Id already opened',
            3   : 'Too many existing Sessions',
            4   : 'On going processes',
            5   : 'Too many opened Connections',
            6   : 'Trust refused',
            10  : 'Trust expired',
            11  : 'Unknown Role',
            100 : 'Unknown Session Id',
            101 : 'Unknown Object Id',
            110 : 'Object creation failed',
            113 : 'Unknown Archive Id',
            202 : 'Unknown Container Id',
            203 : 'Container Ype not supported',
            204 : 'Container WRITE only',
            205 : 'Container Name already exists',
            206 : 'Container Name not found',
            207 : 'Data Type not supported',
            208 : 'Storage full',
            209 : 'Storage busy',
            300 : 'Unknown Key',
            301 : 'Unknown Key Id',
            302 : 'Unknown Key Type',
            303 : 'Key Size not supported',
            400 : 'Value not found',
            500 : 'Not enough Entropy',
            600 : 'Attestation failed',
            790 : 'Certificate Problem - Check server for detailed error'
        }
        return switcher.get(status_code,'Unknown Error')


    def run(self):
        self.mainwindow.mainloop()

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('-sc', '--server_cert', default='../../pki/server.crt', help='Server Certificate File')
    ap.add_argument('-cc', '--client_cert', default='../../pki/client.crt', help='Client Certificate File')
    ap.add_argument('-ck', '--client_key',  default='../../pki/client.key', help='Client Key File')
    args = vars(ap.parse_args())

    server_cert = args['server_cert']
    client_cert = args['client_cert']
    client_key  = args['client_key']

    logger.info('Server Certificate [' + server_cert + ']')
    logger.info('Client Certificate [' + client_cert + ']')
    logger.info('Client Key         [' + client_key + ']')

    app = ETSI103457App()
    app.run()
