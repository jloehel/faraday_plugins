"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
import re
from urllib.parse import urlparse

from faraday_plugins.plugins.plugin import PluginXMLFormat
from faraday_plugins.plugins.plugins_utils import resolve_hostname

try:
    import xml.etree.cElementTree as ET

    ETREE_VERSION = ET.VERSION
except ImportError:
    import xml.etree.ElementTree as ET

    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class ZapXmlParser:
    """
    The objective of this class is to parse an xml
    file generated by the zap tool.

    TODO: Handle errors.
    TODO: Test zap output version. Handle what happens
          if the parser doesn't support it.

    TODO: Test cases.

    @param zap_xml_filepath A proper xml generated by zap
    """

    def __init__(self, xml_output):

        tree = self.parse_xml(xml_output)

        if tree is not None:
            self.sites = [data for data in self.get_items(tree)]
        else:
            self.sites = []

    @staticmethod
    def parse_xml(xml_output):
        """
        Open and parse an xml file.

        TODO: Write custom parser to just read the nodes that we need instead of
        reading the whole file.

        @return xml_tree An xml tree instance. None if error.
        """
        try:
            parser = ET.XMLParser(target=ET.TreeBuilder())
            parser.feed(xml_output)
            tree = parser.close()

        except SyntaxError as err:
            print("SyntaxError: %s. %s" % (err, xml_output))
            return None

        return tree

    @staticmethod
    def get_items(tree):
        """
        @return items A list of Host instances
        """
        for node in tree.findall('site'):
            yield Site(node)


def get_attrib_from_subnode(xml_node, subnode_xpath_expr, attrib_name):
    """
    Finds a subnode in the item node and the retrieves a value from it

    @return An attribute value
    """
    global ETREE_VERSION
    node = None

    if ETREE_VERSION[0] <= 1 and ETREE_VERSION[1] < 3:

        match_obj = re.search(
            "([^\@]+?)\[\@([^=]*?)=\'([^\']*?)\'",
            subnode_xpath_expr)

        if match_obj is not None:

            node_to_find = match_obj.group(1)
            xpath_attrib = match_obj.group(2)
            xpath_value = match_obj.group(3)

            for node_found in xml_node.findall(node_to_find):

                if node_found.attrib[xpath_attrib] == xpath_value:
                    node = node_found
                    break
        else:
            node = xml_node.find(subnode_xpath_expr)

    else:
        node = xml_node.find(subnode_xpath_expr)

    if node is not None:
        return node.get(attrib_name)

    return None

def strip_tags(data):
    """
    Remove html tags from a string
    @return Stripped string
    """
    clean = re.compile('<.*?>')
    return re.sub(clean, '', data)

class Site:

    def __init__(self, item_node):

        self.node = item_node

        self.host = self.node.get('host')
        self.ip = resolve_hostname(self.host)
        self.port = self.node.get('port')
        self.ssl = self.node.get('ssl')

        self.items = []
        for alert in self.node.findall('alerts/alertitem'):
            self.items.append(Item(alert))

    def get_text_from_subnode(self, subnode_xpath_expr):
        """
        Finds a subnode in the host node and the retrieves a value from it.

        @return An attribute value
        """
        sub_node = self.node.find(subnode_xpath_expr)
        if sub_node is not None:
            return sub_node.text
        return None


class Item:
    """
    An abstract representation of a Item


    @param item_node A item_node taken from an zap xml tree
    """

    def __init__(self, item_node):

        self.node = item_node
        self.id = self.get_text_from_subnode('pluginid')
        self.name = self.get_text_from_subnode('alert')
        self.severity = self.get_text_from_subnode('riskcode')
        self.desc = self.get_text_from_subnode('desc')
        if self.get_text_from_subnode('solution'):
            self.resolution = self.get_text_from_subnode('solution')
        else:
            self.resolution = ''

        self.ref = []
        if self.get_text_from_subnode('reference'):
            links = self.get_text_from_subnode('reference')
            for link in links.split("</p>"):
                link = link.strip().replace("\n", "")
                if link != "":
                    self.ref.append(strip_tags(link))     

        if self.get_text_from_subnode('cweid'):
            self.ref.append("CWE:" + self.get_text_from_subnode('cweid'))

        if self.get_text_from_subnode('wascid'):
            self.ref.append("WASC:" + self.get_text_from_subnode('wascid'))
       
        self.items = []

        if item_node.find('instances'):
            arr = item_node.find('instances')
        else:
            arr = [item_node]

        for elem in arr:
            uri = elem.find('uri').text
            method = elem.findtext('method', "")
            item = self.parse_uri(uri, method)

            param = elem.findtext("param", "")
            attack = elem.findtext("attack", "")
            if attack and param:
                item["data"] = f"URL:\n {uri}\n Payload:\n {param} = {attack}"
            else:
                item["data"] = f"URL:\n {uri}\n Parameter:\n {param}"

            evidence = elem.findtext("evidence", "")
            if evidence:
                item["data"] = f"URL:\n {uri}\n Parameter:\n {param}\n Evidence:\n {evidence}"
            else:
                item["data"] = f"URL:\n {uri}\n"

            item["pname"] = elem.findtext("param", "")

            self.items.append(item)

    def parse_uri(self, uri, method) -> dict:

        parsed_url = urlparse(uri)
        protocol = parsed_url.scheme
        host = parsed_url.netloc
        port = parsed_url.port
        params = self.extract_params_from_uri(uri)

        return {
            'uri': uri,
            'params': ', '.join(params),
            'host': host,
            'website': f"{protocol}://{host}",
            'protocol': protocol,
            'port': port,
            'method': method,
            'path': parsed_url.path,
            'query': parsed_url.query,
            'data': ""
        }

    @staticmethod
    def extract_params_from_uri(uri):
        params = re.findall("(\w+)=", uri)
        return params if params else ''

    def get_text_from_subnode(self, subnode_xpath_expr):
        """
        Finds a subnode in the host node and the retrieves a value from it.

        @return An attribute value
        """
        sub_node = self.node.find(subnode_xpath_expr)
        if sub_node is not None:
            return sub_node.text

        return None


class ZapPlugin(PluginXMLFormat):
    """
    Example plugin to parse zap output.
    """

    def __init__(self, *arg, **kwargs):
        super().__init__(*arg, **kwargs)
        self.identifier_tag = "OWASPZAPReport"
        self.id = "Zap"
        self.name = "Zap XML Output Plugin"
        self.plugin_version = "0.0.4"
        self.version = "2.10.0"
        self.framework_version = "1.0.0"
        self.options = None

    def parseOutputString(self, output):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.
        """

        parser = ZapXmlParser(output)

        for site in parser.sites:

            host = []
            if site.host != site.ip:
                host = [site.host]
            
            if site.ssl == "true":
                service = "https"
            else: 
                service = "http"

            h_id = self.createAndAddHost(site.ip, hostnames=host)

            s_id = self.createAndAddServiceToHost(h_id, service, "tcp", ports=[site.port], status='open')

            for item in site.items:
                for instance in item.items:

                    self.createAndAddVulnWebToService(
                        h_id,
                        s_id,
                        item.name,
                        strip_tags(item.desc),
                        website=instance['website'],
                        query=instance['query'],
                        severity=item.severity,
                        path=instance['path'],
                        params=instance['params'],
                        method=instance['method'],
                        ref=item.ref,
                        resolution=strip_tags(item.resolution),
                        data=instance["data"],
                        pname=instance["pname"],
                        external_id="ZAP-"+str(item.id)
                    )

        del parser


def createPlugin(ignore_info=False):
    return ZapPlugin(ignore_info=ignore_info)
