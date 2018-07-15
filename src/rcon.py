import logging
import select
import socket
import struct

from .exceptions import RCONAuthenticationError, RCONCommunicationError, RCONError

log = logging.getLogger()
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


# Packet types as decribed in https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Requests_and_Responses
SERVERDATA_AUTH = 3
SERVERDATA_AUTH_RESPONSE = 2
SERVERDATA_EXECCOMMAND = 2
SERVERDATA_RESPONSE_VALUE = 0

MINECRAFT_PORT = 25575


class Connection:
    def __init__(self, address, password, port=MINECRAFT_PORT):
        self._address = address
        self._password = password
        self._port = port
        self._socket = None

        self.connect()
        self.authenticate()

    def _request(self, req_type, body):
        """
        Send single request to the server. Packets must have the following structure:
        +--------------+-------------------------------------+--------------------+
        |    Field     |                Type                 |       Value        |
        +--------------+-------------------------------------+--------------------+
        | Size         | 32-bit little-endian Signed Integer | Varies, see below. |
        | ID           | 32-bit little-endian Signed Integer | Varies, see below. |
        | Type         | 32-bit little-endian Signed Integer | Varies, see below. |
        | Body         | Null-terminated ASCII String        | Varies, see below. |
        | Empty String | Null-terminated ASCII String        | 0x00               |
        +--------------+-------------------------------------+--------------------+

        For more information see https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Basic_Packet_Structure
        """

        # Build payload
        terminated_body = body.encode('utf-8') + b'\x00\x00'
        body_size = struct.calcsize("<ii") + len(terminated_body)

        payload = struct.pack('<iii', body_size, SERVERDATA_EXECCOMMAND, req_type)
        self._socket.sendall(payload + terminated_body)

    def _read_from_socket(self, length):
        """
        Read packets from our socket
        :return:
        """
        data = b""
        while len(data) < length:
            data += self._socket.recv(length - len(data))
        return data

    def read(self):
        payload_data = ""
        while True:
            # Read a packet
            response_length, = struct.unpack('<i', self._read_from_socket(4))  # returns tuple with 1 or 2 entrys
            response_payload = self._read_from_socket(response_length)
            payload_id, payload_type = struct.unpack('<ii', response_payload[:8])
            partial_payload_data, payload_padding = response_payload[8:-2], response_payload[-2:]

            # Sanity checks
            if payload_padding != b'\x00\x00':
                raise RCONError("Incorrect padding")

            # Record the response
            payload_data += partial_payload_data.decode('utf8')

            # If there's nothing more to receive, return the response
            if len(select.select([self._socket], [], [], 0)[0]) == 0:
                return payload_id, payload_data

    def connect(self):
        log.info("Connecting to {}:{}...".format(self._address, self._port))
        if self._socket is not None:
            raise RCONCommunicationError("Already connected")

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self._socket.connect((self._address, self._port))
        log.debug("Connection successfully established".format(self._address, self._port))

    def disconnect(self):
        log.debug("Disconnecting from {}:{}".format(self._address, self._port))
        self._socket.close()
        self._socket = None

    def authenticate(self):
        self._request(SERVERDATA_AUTH, self._password)
        # Check if authentication was successful
        payload_id, _ = self.read()
        if payload_id == -1:
            raise RCONAuthenticationError()
        elif payload_id == 2:
            log.debug("Authentication was successful")
        else:
            raise RCONError("Something went wrong. Response ID of auth was neither -1 or 2!")
