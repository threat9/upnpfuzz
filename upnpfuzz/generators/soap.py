import base64
import enum
import random
import uuid
import binascii
import datetime
from typing import Dict, List, Tuple
from xml.dom.minidom import parseString

import requests

from upnpfuzz.display import print_error, print_status
from upnpfuzz.generators.base import BaseGenerator
from upnpfuzz.utils import parse_url

TIMEOUT = 10


class ActionType(enum.Enum):
    """
    Represents actions type.
    """
    ALL = 0
    IN = 1
    OUT = 2


class Argument:
    """
    Represents argument of the action.
    """
    def __init__(self, name: str, data_type: str, default_value: str, allowed_values: List[str]):
        """
        Initializes the argument.

        Args:
            name (str): The name of the argument.
            data_type (str): The data type of the argument.
            default_value (str): The default value of the argument.
            allowed_list List[str]: The potential list of allowed values.
        """
        self.name = name
        self.data_type = data_type
        self.default_value = default_value
        self.allowed_values = allowed_values

    def print(self) -> None:
        """
        Prints the argument.
        """
        print(f"\t{self.name} - {self.data_type} - {self.default_value} - {self.allowed_values}")


class Action:
    """
    Represents a single action.
    """
    def __init__(
            self,
            control_url: str,
            service_type: str,
            action_name: str,
            action_type: ActionType,
            arguments: List[Argument]
    ):
        """
        Initializes the action.

        Args:
            control_url (str): The control url of the action.
            service_type (str): The service type of the action.
            action_name (str): The name of the action.
            action_type (ActionType): The type of the action either IN our OUT.
            arguments (List[Argument]): The list of arguments of the given action.
        """
        self.control_url = control_url
        self.service_type = service_type
        self.action_name = action_name
        self.action_type = action_type
        self.arguments = arguments

    def print(self) -> None:
        """
        Prints action and the arguments.
        """
        if self.action_type == ActionType.IN:
            print(f" >> {self.control_url} - {self.service_type}")
            print(f" >> {self.service_type}#{self.action_name}")
        else:
            print(f" << {self.control_url} - {self.service_type}")
            print(f" << {self.service_type}#{self.action_name}")

        for argument in self.arguments:
            argument.print()


class SOAPRequest:
    """
    Represents the SOAP request.
    """
    def __init__(self, action: Action, host: str, port: int):
        """
        Initializes the SOAP request.

        Args:
            action (Action): The action that will be triggered in the SOAP request.
            host (str): Target host address.
            port (int): Target port number.
        """
        self.action = action
        self.host = host.encode("utf-8")
        self.port = str(port).encode("utf-8")

    def get_headers_params(self, content_length) -> List[bytes]:
        """
        Retrieves the headers params.

        Returns:
            List[bytes]: The list of headers params.
        """
        headers_params = [
            self.action.control_url.encode("utf-8"),
            self.host,
            self.port,
            str(content_length).encode("utf-8"),
            self.action.service_type.encode("utf-8"),
            self.action.action_name.encode("utf-8"),
        ]
        return headers_params

    @staticmethod
    def finalize_headers(headers_params: List[bytes]) -> bytes:
        """
        Finalizes the headers by filling it with the params.

        Args:
            headers_params (List[bytes]): The params used for the headers.

        Returns:
            bytes: The finalized request.
        """
        control_url, host, port, content_length, service_type, action_name = headers_params
        request = (
            b"POST " + control_url + b" HTTP/1.1\r\n" +
            b"Host: " + host + b":" + port + b"\r\n" +
            b"Content-Length: " + content_length + b"\r\n" +
            b"Content-Type: text/xml\r\n" +
            b"SOAPAction: \"" + service_type + b"#" + action_name + b"\"\r\n" +
            b"\r\n"
        )
        return request

    def get_body_params(self) -> List[bytes]:
        """
        Retrieves the body params.

        Returns:
            List[bytes]: The list of body params.
        """
        request_body = []
        if self.action.action_type == ActionType.IN:
            args = []
            for argument in self.action.arguments:
                args += self._get_argument_value(argument)

            request_body = [
                b"<?xml version=\"1.0\"?>\n",
                b"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n",
                b"<SOAP-ENV:Body>\n",
                b"<m:", self.action.action_name.encode("utf-8"), b" ", b"xmlns:m=\"", self.action.service_type.encode("utf-8"), b"\">\n",
                *args,
                b"</m:", self.action.action_name.encode("utf-8"), b">\n",
                b"</SOAP-ENV:Body>\n",
                b"</SOAP-ENV:Envelope>\n",
            ]

        return request_body

    @staticmethod
    def finalize_body(body_params: List[bytes]) -> bytes:
        """
        Finalizes the body by filling it with the params.

        Args:
            body_params (List[bytes]): The params used for the body.

        Returns:
            bytes: The finalized request.
        """
        return b"".join(body_params)

    @staticmethod
    def _get_argument_value(argument: Argument) -> List[bytes]:
        """
        Retrieve argument value based on the data type.

        Args:
            argument (Argument): The argument that should be used.

        Returns:
            List[bytes]: The list of argument params.
        """
        if argument.allowed_values:
            value = random.choice(argument.allowed_values).encode("utf-8")
        elif argument.default_value:
            value = argument.default_value.encode("utf-8")
        elif argument.data_type == "ui1":
            value = str(random.randint(0, 0xff)).encode("utf-8")
        elif argument.data_type == "ui2":
            value = str(random.randint(0, 0xffff)).encode("utf-8")
        elif argument.data_type == "ui4":
            value = str(random.randint(0, 0xffffffff)).encode("utf-8")
        elif argument.data_type == "i1":
            value = str(random.randint(-0x80, 0x7f)).encode("utf-8")
        elif argument.data_type == "i2":
            value = str(random.randint(-0x8000, 0x7fff)).encode("utf-8")
        elif argument.data_type == "i4":
            value = str(random.randint(-0x80000000, 0x7fffffff)).encode("utf-8")
        elif argument.data_type == "boolean":
            value = random.choice([b"0", b"1", b"true", b"false", b"yes", b"no"])
        elif argument.data_type == "string":
            value = b"192.168.1.4"
        elif argument.data_type == "number":
            value = str(random.uniform(-1.8e30, 1.8e30)).encode("utf-8")
        elif argument.data_type == "fixed.14.14":
            value = str(random.uniform(-1.8e30, 1.8e30)).encode("utf-8")
        elif argument.data_type == "float":
            value = str(random.uniform(-1.8e30, 1.8e30)).encode("utf-8")
        elif argument.data_type == "char":
            value = b"A"
        elif argument.data_type == "date":
            random_date = generate_random_date()

            value = random_date.strftime("%Y-%m-%d").encode("utf-8")
        elif argument.data_type == "dateTime":
            random_date = generate_random_date()

            if random.choice([True, False]):
                hours = random.randint(0, 23)
                minutes = random.randint(0, 59)
                seconds = random.randint(0, 59)

                value = (random_date.strftime('%Y-%m-%d') + f"T{hours:02}:{minutes:02}:{seconds:02}").encode("utf-8")
            else:
                value = random_date.strftime('%Y-%m-%d').encode("utf-8")
        elif argument.data_type == "dateTime.tz":
            random_date = generate_random_date()

            if random.choice([True, False]):
                hours = random.randint(0, 23)
                minutes = random.randint(0, 59)
                seconds = random.randint(0, 59)

                time_part = f"T{hours:02}:{minutes:02}:{seconds:02}"
            else:
                time_part = ""

            if random.choice([True, False]):
                tz_hours = random.randint(-12, 14)
                tz_minutes = random.choice([0, 15, 30, 45])  # Random minutes part of the timezone
                if tz_hours < 0:
                    tz_str = f"-{-tz_hours:02}:{tz_minutes:02}"
                else:
                    tz_str = f"+{tz_hours:02}:{tz_minutes:02}"
                tz_part = tz_str
            else:
                tz_part = ""

            value = (random_date.strftime('%Y-%m-%d') + time_part + tz_part).encode("utf-8")
        elif argument.data_type == "time":
            start_time = datetime.datetime(2000, 1, 1)
            end_time = datetime.datetime(2030, 1, 1)
            random_seconds = random.randint(0, int((end_time - start_time).total_seconds()))
            random_time = start_time + datetime.timedelta(seconds=random_seconds)
            value = random_time.isoformat().encode("utf-8")
        elif argument.data_type == "time.tz":
            offset_hours = random.randint(-12, 14)
            offset_minutes = random.choice([0, 15, 30, 45])
            if offset_hours < 0:
                offset_str = f"-{-offset_hours:02}:{offset_minutes:02}"
            else:
                offset_str = f"+{offset_hours:02}:{offset_minutes:02}"

            start_time = datetime.datetime(2000, 1, 1)
            end_time = datetime.datetime(2030, 1, 1)
            random_seconds = random.randint(0, int((end_time - start_time).total_seconds()))

            random_time = start_time + datetime.timedelta(seconds=random_seconds)
            value = (random_time.isoformat() + offset_str).encode("utf-8")
        elif argument.data_type == "bin.base64":
            value = base64.b64encode(
                b"A" * random.randint(0, 0xff)
            )
        elif argument.data_type == "bin.hex":
            value = binascii.hexlify(
                b"A" * random.randint(0, 0xff)
            )
        elif argument.data_type == "uri":
            value = b"http://127.0.0.1/path"
        elif argument.data_type == "uuid":
            value = str(uuid.uuid4()).encode("utf-8")
        else:
            value = b"A" * random.randint(0, 0xff)

        return [
            b"<", argument.name.encode("utf-8"), b">",
            value,
            b"</", argument.name.encode("utf-8"), b">\n",
        ]


class SOAPGenerator(BaseGenerator):
    """
    The SOAP request generator.
    """
    name = "soap"

    def __init__(self, url: str):
        """
        Initializes the SOAP generator.

        Args:
            url (str): The url address of the target.
        """
        self.actions = []
        self.url = url
        self.base_url, self.host, self.port = parse_url(url)

    def generate_grammar(self, soap_type: ActionType) -> bool:
        """
        Generates grammar for SOAP.

        Args:
            soap_type (ActionType): The soap type that should be targeted.

        Returns:
            bool: Returns true if generating grammar was successful or false it failed.
        """
        print_status(f"requesting: {self.url}")
        try:
            response = requests.get(self.url, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            print_error("failed to retrieve the xml")
            return False

        xml = parseString(response.content)

        for service in xml.getElementsByTagName("service"):
            scpd_url = service.getElementsByTagName("SCPDURL")[0].firstChild.data
            control_url = service.getElementsByTagName("controlURL")[0].firstChild.data
            service_type = service.getElementsByTagName("serviceId")[0].firstChild.data

            if "://" not in scpd_url:
                if not scpd_url.startswith("/"):
                    scpd_url = "/" + scpd_url
                scpd_url = self.base_url + scpd_url

            if not control_url.startswith("/"):
                control_url = "/" + control_url

            print_status(f"requesting: {scpd_url}")
            response = requests.get(scpd_url, timeout=TIMEOUT)
            xml = parseString(response.content)

            self._process_service(xml, control_url, service_type, soap_type)

        return True if self.actions else False

    def _process_service(self, xml, control_url: str, service_type: str, soap_type: ActionType) -> None:
        """
        Process the specified service.

        Args:
            xml: The xml object to parse.
            control_url (str): The control url of the action.
            service_type (str): The service type of the action.
        """
        state_variables = self._get_state_variables(xml)

        for action in xml.getElementsByTagName("action"):
            action_name = action.getElementsByTagName("name")[0].firstChild.data
            action_type = ActionType.OUT
            arguments = []

            for argument in action.getElementsByTagName("argument"):
                argument_name = argument.getElementsByTagName("name")[0].firstChild.data
                argument_related_state_variable = argument.getElementsByTagName("relatedStateVariable")[0].firstChild.data

                (data_type, default_value, allowed_values) = state_variables[argument_related_state_variable]
                arguments.append(
                    Argument(argument_name, data_type, default_value, allowed_values)
                )

                if argument.getElementsByTagName("direction")[0].firstChild.data == "in":
                    action_type = ActionType.IN

            if soap_type == ActionType.ALL or action_type == soap_type:
                self.actions.append(
                    Action(control_url, service_type, action_name, action_type, arguments)
                )

    @staticmethod
    def _get_state_variables(xml) -> Dict[str, Tuple[str, str, List[str]]]:
        """
        Retrieves the state variables.

        Args:
            xml: The xml object to parse.

        Returns:
            Dict[str, Tuple[str, str, List[str]]]: Packed values that includes data type, default values and allowed values.
        """
        state_variables = {}

        for state_variable in xml.getElementsByTagName("stateVariable"):
            name = state_variable.getElementsByTagName("name")[0].firstChild.data
            data_type = state_variable.getElementsByTagName("dataType")[0].firstChild.data

            default_value = ""
            res = state_variable.getElementsByTagName("defaultValue")
            if res and res[0].firstChild:
                default_value = res[0].firstChild.data

            allowed_values = []
            for allowed_value in state_variable.getElementsByTagName("allowedValue"):
                allowed_values.append(allowed_value.firstChild.data)

            state_variables[name] = (data_type, default_value, allowed_values)
        return state_variables

    def get_request(self) -> SOAPRequest:
        """
        Retrieve SOAP request for random action.

        Returns:
            SOAPRequest: The SOAP request for random action.
        """
        action = random.choice(self.actions)
        return SOAPRequest(action, self.host, self.port)

    def list(self) -> None:
        """
        Lists all actions for the target address.
        """
        print(f"SOAP: {self.host}:{self.port} ")
        for action in self.actions:
            action.print()


def generate_random_date() -> datetime:
    start_date = datetime.datetime(2000, 1, 1)
    end_date = datetime.datetime(2030, 1, 1)

    delta_days = random.randint(0, (end_date - start_date).days)
    random_date = start_date + datetime.timedelta(days=delta_days)

    return random_date
