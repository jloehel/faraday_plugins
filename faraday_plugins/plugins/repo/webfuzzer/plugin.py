#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import absolute_import
from __future__ import print_function

from __future__ import with_statement
from faraday.client.plugins import core
from faraday.client.model import api
import re
import os
import pprint
import sys


current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class WebfuzzerParser(object):
    """
    The objective of this class is to parse an xml file generated by the webfuzzer tool.

    TODO: Handle errors.
    TODO: Test webfuzzer output version. Handle what happens if the parser doesn't support it.
    TODO: Test cases.

    @param webfuzzer_filepath A proper output generated by webfuzzer
    """

    def __init__(self, webfuzzer_filepath):
        self.filepath = webfuzzer_filepath

        with open(self.filepath, "r") as f:
            try:
                data = f.read()
                f.close()
                m = re.search(
                    "Scan of ([\w.]+):([\d]+) \[([/\w]+)\] \(([\w.]+)\)", data)
                self.hostname = m.group(1)
                self.port = m.group(2)
                self.uri = m.group(3)
                self.ipaddress = m.group(4)

                m = re.search("Server header:\n\n([\w\W]+)\n\n\n", data)
                self.header = m.group(1)

                self.items = []

                pattern = r'\((POST|GET)\): ([\w\W]*?) \]--'

                for m in re.finditer(pattern, data, re.DOTALL):

                    method = m.group(1)
                    info = re.search(
                        "^([\w\W]+)\(([\w\W]+)\)\n--\[ ([\w\W]+)$", m.group(2))

                    vuln = {'method': m.group(1), 'desc': info.group(
                        1), 'url': info.group(2), 'resp': info.group(3)}
                    self.items.append(vuln)

            except SyntaxError as err:
                print("SyntaxError: %s. %s" % (err, filepath))
                return None


class WebfuzzerPlugin(core.PluginBase):
    """
    Example plugin to parse webfuzzer output.
    """

    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Webfuzzer"
        self.name = "Webfuzzer Output Plugin"
        self.plugin_version = "0.0.2"
        self.version = "0.2.0"
        self.options = None
        self._current_output = None
        self.host = None
        self._command_regex = re.compile(
            r'^(sudo webfuzzer|webfuzzer|\.\/webfuzzer).*?')
        self._completition = {'': '__Usage: ./webfuzzer -G|-P URL [OPTIONS]',
                              '-G': '<url>	get this as starting url (with parameters)',
                              '-P': '<url>	post this as starting url (with parameters)',
                              '-x': 'html output (txt default)',
                              '-c': 'use cookies',
                              '-C': '<cookies>	set this cookie(s) **',
                              '-s': 'check for sql, asp, vb, php errors (default)',
                              '-d': 'check for directory traversal *',
                              '-p': 'check for insecure perl open or xss *',
                              '-e': 'check for execution through shell escapes or xss *',
                              '-a': 'set all of the above switches on *',
                              }

        self._output_path = None

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        if self._output_path is None:
            return False
        else:
            if not os.path.exists(self._output_path):
                return False

            parser = WebfuzzerParser(self._output_path)

            h_id = self.createAndAddHost(parser.ipaddress)

            i_id = self.createAndAddInterface(
                h_id, parser.ipaddress, ipv4_address=parser.ipaddress, hostname_resolution=[parser.hostname])

            first = True
            for item in parser.items:
                if first:
                    s_id = self.createAndAddServiceToInterface(h_id, i_id, parser.port,
                                                               "tcp",
                                                               ports=[parser.port])
                    first = False

                v_id = self.createAndAddVulnWebToService(h_id, s_id, name=item['desc'],
                                                         path=item['url'], response=item[
                                                             'resp'],
                                                         method=item['method'], website=parser.hostname)

            n_id = self.createAndAddNoteToService(h_id, s_id, "website", "")
            n2_id = self.createAndAddNoteToNote(
                h_id, s_id, n_id, parser.hostname, "")

        del parser

        return True

    def processCommandString(self, username, current_path, command_string):
        """
        """
        host = re.search("\-([G|P]) ([\w\.\-]+)", command_string)

        if host is not None:
            self.host = host.group(2)
            self._output_path = current_path + "/" + self.host + ".txt"
        return None


def createPlugin():
    return WebfuzzerPlugin()

if __name__ == '__main__':
    parser = WebfuzzerParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print(item)


# I'm Py3
