"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json
import re
from faraday_plugins.plugins.plugin import PluginJsonFormat

__author__ = "Blas Moyano"
__copyright__ = "Copyright (c) 2020, Infobyte LLC"
__credits__ = ["Blas Moyano"]
__license__ = ""
__version__ = "0.0.3"
__maintainer__ = "Blas Moyano"
__email__ = "bmoyano@infobytesec.com"
__status__ = "Development"


class WhatWebJsonParser:

    def __init__(self, json_output):
        list_data = json.loads(json_output)
        self.host_whatweb = []
        for info in list_data:
            try:
                server_info = info['plugins']['HTTPServer']
            except KeyError:
                server_info = {}

            try:
                ip_info = info['plugins']['IP']
            except KeyError:
                ip_info = {}

            try:
                country_info = info['plugins']['Country']
            except KeyError:
                country_info = {}

            whatweb_data = {
                "url": info.get('target', None),
                "os": None if not server_info else server_info.get('os', None),
                "os_detail": "Unknown" if not server_info else server_info.get('string', 'Unknown'),
                "ip": ['0.0.0.0'] if ip_info is None else ip_info.get('string', None),
                "country": "" if country_info is None else country_info.get('string', "")
            }
            self.host_whatweb.append(whatweb_data)


class WhatWebPlugin(PluginJsonFormat):

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.id = "whatweb"
        self.name = "WhatWebPlugin"
        self.plugin_version = __version__
        self._command_regex = re.compile(r'^(sudo whatweb|whatweb|\.\/whatweb)\s+.*?')
        self._use_temp_file = True
        self._temp_file_extension = "json"
        self.version = "0.5.5"
        self.json_arg_re = re.compile(r"^.*(--log-json(=|[\s*])[^\s]+).*$")
        self.json_keys = {'target', 'http_status', 'plugins'}

    def processCommandString(self, username, current_path, command_string):
        """
        Adds the --json-log parameter to get json output to the command string that the
        user has set.
        """
        super().processCommandString(username, current_path, command_string)
        arg_match = self.json_arg_re.match(command_string)
        if arg_match is None:
            return re.sub(r"(^.*?whatweb)",
                          r"\1 --log-json %s" % self._output_file_path,
                          command_string)
        else:
            return re.sub(arg_match.group(1),
                          r"--log-json %s" % self._output_file_path,
                          command_string)

    def parseOutputString(self, output):
        parser = WhatWebJsonParser(output)
        for whatweb_data in parser.host_whatweb:
            desc = f"{whatweb_data['os_detail']} - {whatweb_data['country']}"
            if whatweb_data['os'] is None:
                datail_os = "Unknown"
            else:
                datail_os = whatweb_data['os'][0]

            self.createAndAddHost(whatweb_data['ip'][0],
                                  os=datail_os,
                                  hostnames=whatweb_data['url'],
                                  description=desc)


def createPlugin(ignore_info=False):
    return WhatWebPlugin(ignore_info=ignore_info)
