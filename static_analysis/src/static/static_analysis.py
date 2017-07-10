import logging
import os
import re
import sys
from xml.etree import ElementTree

# Imports needed for SQLAlchemy to work
from common.models import certificate, scenario_settings, sys_certificates_table, user, user_certificates_table, static_analysis
from common.models.static_analysis import StaticAnalysisResults, StaticAnalysisResult
from common.models.vuln_type import VulnType

logger = logging.getLogger(__name__)


# increase recursion limit
sys.setrecursionlimit(40000)


class Node:
    def __init__(self, method_defn):
        self.children = []
        self.parents = []
        self.method_defn = method_defn

    def __repr__(self):
        return self.method_defn

    def add_child(self, child_id):
        self.children.append(child_id)

    def add_parent(self, parent_id):
        self.parents.append(parent_id)


class StaticAnalyzer:

    def __init__(self):
        # nodes of the method call graph for all methods
        self.NODES = {}
        # all method names (including class name)
        self.METHODS = set()
        # array of (method name (including class name), method) tuples for each class name
        self.CLASS = {}
        # (method name (including class name), vulnerability type) tuples for all possibly vulnerable overwritten methods
        self.VULN = set()
        # dict of the name attributes of the Android Manifest and the tags of the corresponding xml elements
        self.MANIFEST = {}

    def result_with_tag_from_manifest(self, apk_folder, vuln, mth_nm):
        # create a fully qualified class name from the method name
        cls_nm = re.sub("^L", "", mth_nm)
        if "$" in cls_nm:
            cls_nm = cls_nm.split("$")[0]
        else:
            cls_nm = cls_nm.split(";")[0]
        cls_nm = cls_nm.replace("/", ".")

        result = set()
        for name_attrib,tag in self.MANIFEST.iteritems():
            if tag == 'activity' and cls_nm == name_attrib:
                result.add(StaticAnalysisResult(apk_folder, vuln[0], cls_nm, vuln[1]))

        return result

    # Returns entry points
    # Traverses from the possibly vulnerable method into its parents (calling method or constructor of the methods
    # class), from them into their parents and so on.
    # Stops and returns
    def traverse(self, apk, vuln, node, seen, traversed):
        traversed.add(node.method_defn)

        result = set()
        if not node.parents:
            class_nm = node.method_defn.split("->")[0]

            for activity_name, method in self.CLASS[class_nm]:
                if "init" in activity_name and activity_name in self.NODES and activity_name not in seen:
                    # no calling method, continue traversing from the constructor of the methods class
                    seen.add(activity_name)
                    result |= self.traverse(apk, vuln, self.NODES[activity_name], seen, traversed)
                elif activity_name in seen:
                    result |= self.result_with_tag_from_manifest(apk, vuln, activity_name)
        else:
            for parent in node.parents:
                if parent not in traversed:
                    p_node = self.NODES[parent]
                    result |= self.traverse(apk, vuln, p_node, seen, traversed)

        return result

    # Build a method call graph by creating Nodes for all classes and linking them to their children and parent
    # Add created nodes to NODES
    def parse_methods(self):
        # build NODES mcg
        for cls, methods in self.CLASS.iteritems():
            for meth_name, method in methods:
                if meth_name in self.NODES:
                    node = self.NODES[meth_name]
                else:
                    node = Node(meth_name)

                for inv in re.findall(r"invoke-.*", method):
                    t_inv = inv.split()[-1]
                    if t_inv in self.METHODS:

                        if t_inv in self.NODES:
                            c_node = self.NODES[t_inv]
                        else:
                            c_node = Node(t_inv)
                        c_node.add_parent(meth_name)
                        self.NODES[t_inv] = c_node

                        node.add_child(t_inv)

                # add static fields with http/https urls to method call graph - as leaf nodes
                for sget in re.findall(r"sget-object (.*Ljava/lang/String;)", method):
                    t_sget = sget.split()[-1]
                    if (t_sget, VulnType.http.value) in self.VULN or (t_sget, VulnType.https.value) in self.VULN:

                        if t_sget in self.NODES:
                            c_node = self.NODES[t_sget]
                        else:
                            c_node = Node(t_sget)
                        c_node.add_parent(meth_name)
                        self.NODES[t_sget] = c_node

                        node.add_child(t_sget)

                self.NODES[meth_name] = node

    def find(self, regex, string):
        return re.search(regex, string).groups(0)[0]

    # Parse a smali file
    # Check for possibly vulnerable methods and add their names (including class name) them to the VULN array
    # Adds the methods of this class to METHODS
    # Sets the CLASS entry for this class
    def parse_smali_file(self, path):
        f_content = open(path).read()

        class_name = self.find("\.class(.*)", f_content).split()[-1]
        methods = re.findall(r"\.method.*?\.end method", f_content, re.S)

        trustmanager = re.findall(r"(\.implements Ljavax/net/ssl/X509TrustManager;)", f_content)
        hostnameverifier = re.findall(r"(\.implements Ljavax/net/ssl/HostnameVerifier;)", f_content)
        webviewclient = re.findall(r"(\.super Landroid/webkit/WebViewClient;)", f_content)
        # helper variables for finding out if web view is vulnerable
        on_received_ssl_error = False
        webviewclient_key = None

        meth_arr = []

        for method in methods:
            method_name = self.find("\.method(.*)", method).split()[-1]
            key = "%s->%s" % (class_name, method_name)

            # add constructor (init) to possibly vulnerable methods if trustmanager is implemented
            if trustmanager and "init" in method_name:
                # add key to TM
                self.VULN.add((key, VulnType.trust_manager.value))
            # add constructor (init) to possibly vulnerable methods if hostnameverifier is implemented
            elif hostnameverifier and "init" in method_name:
                self.VULN.add((key, VulnType.hostname_verifier.value))
            elif webviewclient:
                if "init" in method_name:
                    webviewclient_key = key
                elif "onReceivedSslError" in method_name:
                    on_received_ssl_error = True

            if "<clinit>" in method_name:
                self.add_clinit_string_vulns(method)
            else:
                self.add_method_string_vulns(method, key)

            # public final strings?

            self.METHODS.add(key)
            meth_arr.append((key, method))

        # add constructor (init) to possibly vulnerable methods if
        # webviewclient is extended and onReceivedSslError overwritten
        if on_received_ssl_error and webviewclient_key:
            self.VULN.add((webviewclient_key, VulnType.web_view_client.value))

        self.CLASS[class_name] = meth_arr

    def add_clinit_string_vulns(self, method):
        http_strings = re.findall(r"const-string (v[^,]*), \"(http://.*)\"\s*sput-object (v[^,]*), (.*)", method, re.M)
        if http_strings:
            for var1, url, var2, field in http_strings:
                if var1 == var2:
                    self.VULN.add((field, VulnType.http.value))

        https_strings = re.findall(
            r"const-string (v[^,]*), \"(https://.*)\"\s*sput-object (v[^,]*), (.*)",
            method,
            re.M)
        if https_strings:
            for var1, url, var2, field in https_strings:
                if var1 == var2:
                    self.VULN.add((field, VulnType.https.value))

    def add_method_string_vulns(self, method, key):
        http_strings = re.search(r"const-string .*, \"(http://.*)\"", method)
        if http_strings:
            self.VULN.add((key, VulnType.http.value))

        https_strings = re.search(r"const-string .*, \"(https://.*)\"", method)
        if https_strings:
            self.VULN.add((key, VulnType.https.value))

    # Processes the apk in the given path
    # Add the names (including class name) of possibly vulnerable methods to VULN
    # Build a method call graph NODE
    def process_apk(self, apk_path):
        for path, folders, files in os.walk(apk_path):
            for file in files:
                if file.endswith(".smali") and not re.match("R\$.*", file):
                    f_path = os.path.join(path, file)

                    self.parse_smali_file(f_path)

        self.parse_methods()

    # Parses the Android Manifest
    # Saves the the tag of the corresponding xml element under the value of it's name attribute in MANIFEST
    def parse_manifest(self, apk_path):
        xml = "%s/AndroidManifest.xml" % apk_path
        tree = ElementTree.parse(xml)

        # get package name from root
        root = tree.getroot()
        package = root.attrib["package"]
        min_sdk_version = None
        target_sdk_version = None
        platform_build_version_code = None

        for child in tree.iter():
            for attrib_name,attrib_value in child.attrib.iteritems():

                # get value of only android:name attribute name
                if "{http://schemas.android.com/apk/res/android}name" in attrib_name:
                    if attrib_value.startswith("."):
                        # prepend package name
                        attrib_value = "%s%s" % (package, attrib_value)
                    self.MANIFEST[attrib_value] = child.tag

                if "{http://schemas.android.com/apk/res/android}minSdkVersion" in attrib_name:
                    min_sdk_version = attrib_value

                if "{http://schemas.android.com/apk/res/android}targetSdkVersion" in attrib_name:
                    target_sdk_version = attrib_value

                if "platformBuildVersionCode" in attrib_name:
                    platform_build_version_code = attrib_value

        return package, min_sdk_version, target_sdk_version or platform_build_version_code

    # Analyses the decoded APK in the given path
    def analyze_statically(self, apk_path, apk_filename):
        package, min_sdk_version, target_sdk_version = self.parse_manifest(apk_path)
        self.process_apk(apk_path)

        results = set()

        for vuln in self.VULN:
            if vuln[0] in self.NODES:
                node = self.NODES[vuln[0]]
                results |= self.traverse(apk_path, vuln, node, set(), set())

        # also add HTTP and HTTPS vulntype results as HTTPS_HTTP vulntype results
        addtl_results = set()
        for r in results:
            if r.vuln_type in [VulnType.http.value, VulnType.https.value]:
                nw = StaticAnalysisResult(r.apk_folder, r.vuln_entry, r.activity_name, VulnType.https_http.value)
                addtl_results |= {nw}

        results |= addtl_results

        return StaticAnalysisResults(apk_filename, package, min_sdk_version, target_sdk_version, list(results))
