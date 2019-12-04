"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from faraday_plugins.plugins.plugin import PluginXMLFormat
import re
import os

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG

    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET

    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

current_path = os.path.abspath(os.getcwd())

__author__ = "Micaela Ranea Sanchez"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato", "Federico Kirschbaum",
               "Micaela Ranea Sanchez", "German Riera"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Micaela Ranea Sanchez"
__email__ = "mranea@infobytesec.com"
__status__ = "Development"


class NexposeFullXmlParser:
    """
    The objective of this class is to parse Nexpose's XML 2.0 Report.

    TODO: Handle errors.
    TODO: Test nexpose output version. Handle what happens if the parser doesn't support it.
    TODO: Test cases.

    @param xml_filepath A proper xml generated by nexpose
    """

    def __init__(self, xml_output):
        tree = self.parse_xml(xml_output)
        self.vulns = self.get_vuln_definitions(tree)

        if tree:
            self.items = self.get_items(tree, self.vulns)
        else:
            self.items = []

    def parse_xml(self, xml_output):
        """
        Open and parse an xml file.

        TODO: Write custom parser to just read the nodes that we need instead of
        reading the whole file.

        @return xml_tree An xml tree instance. None if error.
        """
        try:
            tree = ET.fromstring(xml_output)
        except SyntaxError as err:
            print("SyntaxError: %s. %s" % (err, xml_output))
            return None

        return tree

    def parse_html_type(self, node: ET.Element) -> str:
        """
        Parse XML element of type HtmlType

        @return ret A string containing the parsed element
        """
        ret = ""
        tag: str = node.tag.lower()
        if tag == 'containerblockelement':
            if len(list(node)) > 0:
                for child in list(node):
                    ret += self.parse_html_type(child)
            else:
                ret += node.text.strip() if node.text else ""
        if tag == 'listitem':
            if len(list(node)) > 0:
                for child in list(node):
                    ret += self.parse_html_type(child)
            else:
                ret = node.text.strip() if node.text else ""
        if tag == 'orderedlist':
            i = 1
            for item in list(node):
                ret += "\t" + str(i) + " " + self.parse_html_type(item) + "\n"
                i += 1
        if tag == 'paragraph':
            if len(list(node)) > 0:
                for child in list(node):
                    ret += self.parse_html_type(child)
            else:
                ret += node.text.strip() if node.text else ""
        if tag == 'unorderedlist':
            for item in list(node):
                ret += "\t" + "* " + self.parse_html_type(item) + "\n"
        if tag == 'urllink':
            if node.get('text'):
                ret += node.text.strip() + " "
            last = ""
            for attr in node.attrib:
                if node.get(attr) and node.get(attr) != node.get(last):
                    ret += node.get(attr) + " "
                last = attr

        return ret

    def parse_tests_type(self, node, vulnsDefinitions):
        """
        Parse XML element of type TestsType

        @return vulns A list of vulnerabilities according to vulnsDefinitions
        """
        vulns = list()

        for tests in node.findall('tests'):
            for test in tests.iter('test'):
                vuln = dict()
                if test.get('id').lower() in vulnsDefinitions:
                    vuln = vulnsDefinitions[test.get('id').lower()].copy()
                    key = test.get('key', '')
                    vuln['pci'] = test.get('pci-compliance-status')
                    vuln['vulnerable_since'] = test.get('vulnerable-since')
                    vuln['scan_id'] = test.get('scan-id')
                    if key.startswith('/'):
                        # It has the path where the vuln was found
                        # Example key: "/comments.asp||content"
                        vuln['path'] = key[:key.find('|')]
                    for desc in list(test):
                        vuln['desc'] += self.parse_html_type(desc)
                    vulns.append(vuln)
        return vulns

    def get_vuln_definitions(self, tree):
        """
        @returns vulns A dict of Vulnerability Definitions
        """
        vulns = dict()
        # CVSS V3
        SEVERITY_MAPPING_DICT = {'0': 'info', '1': 'low', '2': 'low', '3': 'low', '4': 'med', '5': 'med', '6': 'med',
                                 '7': 'high', '8': 'high', '9': 'critical', '10': 'critical'}

        for vulnsDef in tree.iter('VulnerabilityDefinitions'):
            for vulnDef in vulnsDef.iter('vulnerability'):
                vid = vulnDef.get('id').lower()
                vector = vulnDef.get('cvssVector')
                vuln = {
                    'desc': "",
                    'name': vulnDef.get('title'),
                    'refs': ["vector: " + vector, vid],
                    'resolution': "",
                    'severity': SEVERITY_MAPPING_DICT[vulnDef.get('severity')],
                    'tags': list(),
                    'is_web': vid.startswith('http-'),
                    'risk': vulnDef.get('riskScore'),
                }

                for item in list(vulnDef):
                    if item.tag == 'description':
                        for htmlType in list(item):
                            vuln['desc'] += self.parse_html_type(htmlType)
                    if item.tag == 'exploits':
                        for exploit in list(item):
                            if exploit.get('title') and exploit.get('link') and exploit.get('type') \
                                    and exploit.get('sklLevel'):
                                title = exploit.get('title').encode(
                                    "ascii", errors="backslashreplace").strip()
                                link = exploit.get('link').encode(
                                    "ascii", errors="backslashreplace").strip()
                                type = exploit.get('type').encode(
                                    "ascii", errors="backslashreplace").strip()
                                skillLevel = exploit.get('sklLevel').encode(
                                    "ascii", errors="backslashreplace").strip()
                                vuln['refs'].append(title + b' ' + link +  b' ' + type +  b' ' + skillLevel)
                    if item.tag == 'malware':
                        for names in item.findall("name"):
                            nameMalware = names.text
                            vuln['refs'].append(nameMalware)
                    if item.tag == 'references':
                        for ref in list(item):
                            if ref.text:
                                rf = ref.text.encode(
                                    "ascii", errors="backslashreplace").strip()
                                vuln['refs'].append(rf)
                    if item.tag == 'solution':
                        for htmlType in list(item):
                            vuln['resolution'] += self.parse_html_type(htmlType)
                    """
                    # there is currently no method to register tags in vulns
                    if item.tag == 'tags':
                        for tag in list(item):
                            vuln['tags'].append(tag.text.lower())
                    """
                vulns[vid] = vuln
        return vulns

    def get_items(self, tree, vulns):
        """
        @return hosts A list of Host instances
        """

        hosts = list()

        for nodes in tree.iter('nodes'):
            for node in nodes.iter('node'):
                host = dict()
                host['name'] = node.get('address')
                host['mac'] = node.get('hardware-address')
                host['hostnames'] = list()
                host['os'] = list()
                host['services'] = list()
                host['fingerprints'] = list()
                host['fingerprints_software'] = list()
                host['vulns'] = self.parse_tests_type(node, vulns)
                host['scan-template'] = node.get('scan-template')
                host['scan-name'] = node.get('scan-name')
                host['scan-importance'] = node.get('scan-importance')
                host['risk-score'] = node.get('risk-score')

                for names in node.iter('names'):
                    for name in list(names):
                        host['hostnames'].append(name.text)

                for fingerprints in node.iter('fingerprints'):
                    for os_data in fingerprints.iter('os'):
                        data = {
                            'certainty': os_data.get('certainty'),
                            'vendor': os_data.get('vendor'),
                            'family': os_data.get('family'),
                            'product': os_data.get('product'),
                            'version': os_data.get('version'),
                            'arch': os_data.get('arch'),
                            'device-class': os_data.get('device-class'),
                        }
                        host['os'].append(data)

                    for fingerprints_tag in fingerprints.iter('fingerprint'):
                        data_fingerprints_tag = {
                            'certainty': fingerprints_tag.get('certainty'),
                            'product': fingerprints_tag.get('product'),
                            'version': fingerprints_tag.get('version'),
                        }
                        host['fingerprints'].append(data_fingerprints_tag)

                for endpoints in node.iter('endpoints'):
                    for endpoint in list(endpoints):
                        svc = {
                            'protocol': endpoint.get('protocol'),
                            'port': endpoint.get('port'),
                            'status': endpoint.get('status'),
                        }
                        for services in endpoint.iter('services'):
                            for service in list(services):
                                svc['name'] = service.get('name')
                                svc['vulns'] = self.parse_tests_type(
                                    service, vulns)
                                for configs in service.iter('configurations'):
                                    for config in list(configs):
                                        if "banner" in config.get('name'):
                                            svc['version'] = config.get('name')
                        host['services'].append(svc)

                for softwaretag in node.iter('software'):
                    for soft_data in softwaretag.iter('fingerprint'):
                        data_soft = {
                            'certainty': soft_data.get('certainty'),
                            'vendor': soft_data.get('vendor'),
                            'family': soft_data.get('family'),
                            'product': soft_data.get('product'),
                            'version': soft_data.get('version'),
                        }
                        host['fingerprints_software'].append(data_soft)
                hosts.append(host)

        return hosts


class NexposeFullPlugin(PluginXMLFormat):
    """
    Example plugin to parse nexpose output.
    """

    def __init__(self):
        super().__init__()
        self.identifier_tag = "NexposeReport"
        self.id = "NexposeFull"
        self.name = "Nexpose XML 2.0 Report Plugin"
        self.plugin_version = "0.0.1"
        self.version = "Nexpose Enterprise 5.7.19"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._command_regex = re.compile(r'^(sudo nexpose|\.\/nexpose).*?')

    def parseOutputString(self, output, debug=False):

        parser = NexposeFullXmlParser(output)

        for item in parser.items:
            h_id = self.createAndAddHost(item['name'], item['os'], hostnames=item['hostnames'],
                                         scan_template=item['scan-template'], site_name=item['scan-name'],
                                         site_importance=item['scan-importance'], risk_score=item['risk-score'],
                                         fingerprints=item['fingerprints'],
                                         fingerprints_software=item['fingerprints_software']
                                         )
            pattern = '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            if not item['mac']:
                item['mac'] = '0000000000000000'
                match = re.search(pattern, item['mac'])
            else:
                match = re.search(pattern, item['mac'])
            if match:
                i_id = self.createAndAddInterface(
                    h_id,
                    item['name'],
                    mac=item['mac'],
                    ipv4_address=item['name'],
                    hostname_resolution=item['hostnames'],
                    scan_template=item['scan-template'],
                    site_name=item['scan-name'],
                    site_importance=item['scan-importance'],
                    risk_score=item['risk-score'],
                    fingerprints=item['fingerprints'],
                    fingerprints_software=item['fingerprints_software'],
                )
            else:
                i_id = self.createAndAddInterface(
                    h_id,
                    item['name'],
                    mac=':'.join(item['mac'][i:i + 2] for i in range(0, 12, 2)),
                    ipv4_address=item['name'],
                    hostname_resolution=item['hostnames'])

            for v in item['vulns']:
                v['data'] = {"vulnerable_since": v['vulnerable_since'], "scan_id": v['scan_id'], "PCI": v['pci']}
                v_id = self.createAndAddVulnToHost(
                    h_id,
                    v['name'],
                    v['desc'],
                    v['refs'],
                    v['severity'],
                    v['resolution'],
                    v['vulnerable_since'],
                    v['scan_id'],
                    v['pci']
                )

            for s in item['services']:
                web = False
                version = s.get("version", "")

                s_id = self.createAndAddServiceToInterface(
                    h_id,
                    i_id,
                    s['name'],
                    s['protocol'],
                    ports=[str(s['port'])],
                    status=s['status'],
                    version=version)

                for v in s['vulns']:

                    if v['is_web']:
                        v_id = self.createAndAddVulnWebToService(
                            h_id,
                            s_id,
                            v['name'],
                            v['desc'],
                            v['refs'],
                            v['severity'],
                            v['resolution'],
                            v['risk'],
                            path=v.get('path', ''))
                    else:
                        v_id = self.createAndAddVulnToService(
                            h_id,
                            s_id,
                            v['name'],
                            v['desc'],
                            v['refs'],
                            v['severity'],
                            v['resolution'],
                            v['risk']
                        )

        del parser

    def processCommandString(self, username, current_path, command_string):
        return None

    def setHost(self):
        pass


def createPlugin():
    return NexposeFullPlugin()


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) == 2:
        report_file = sys.argv[1]
        if os.path.isfile(report_file):
            plugin = createPlugin()
            plugin.processReport(report_file)
            print(plugin.get_json())
        else:
            print(f"Report not found: {report_file}")
    else:
        print(f"USAGE {sys.argv[0]} REPORT_FILE")
# I'm Py3