import os
import re
import sys
from xml.etree import ElementTree


# increase recursion limit
sys.setrecursionlimit(40000)


class StaticAnalysisResults:
    def __init__(self, apk_filename, package, min_sdk_version, target_sdk_version, result_list):
        self.apk_filename = apk_filename
        self.package = package
        self.min_sdk_version = min_sdk_version
        self.target_sdk_version = target_sdk_version
        self.result_list = result_list

    def __json__(self):
        return {
            'apk_filename': self.apk_filename,
            'package': self.package,
            'min_sdk_version': self.min_sdk_version,
            'target_sdk_version': self.target_sdk_version,
            'result_list': self.result_list}


class StaticAnalysisResult:
    def __init__(self, apk_folder, vuln_entry, activity_name, tag, vuln_type):
        self.apk_folder = apk_folder
        self.vuln_entry = vuln_entry
        self.activity_name = activity_name
        self.tag = tag
        self.vuln_type = vuln_type

    def __json__(self):
        return {
            'apk_folder': self.apk_folder,
            'vuln_entry': self.vuln_entry,
            'activity_name': self.activity_name,
            'tag': self.tag,
            'vuln_type': {
                'value': self.vuln_type
            }}

    def __key(self):
        return (self.apk_folder, self.vuln_entry, self.activity_name, self.tag, self.vuln_type)

    def __eq__(self, other):
        return self.__key() == other.__key()

    def __hash__(self):
        return hash(self.__key())


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
        # array of (method name (including class name), method) tuples for each class name, TODO: better only method name??
        self.CLASS = {}
        # (method name (including class name), vulnerability type) tuples for all possibly vulnerable overwritten methods
        self.VULN = []
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

        result = list()
        for name_attrib,tag in self.MANIFEST.iteritems():
            if cls_nm in name_attrib:
                result.append(StaticAnalysisResult(apk_folder, vuln[0], cls_nm, tag, vuln[1]))

        return result

    # Returns entry points
    # Traverses from the possibly vulnerable method into its parents (calling method or constructor of the methods
    # class), from them into their parents and so on.
    # Stops and returns
    def traverse(self, apk, vuln, node, seen):
        result = list()
        if not node.parents:
            class_nm = node.method_defn.split("->")[0]

            for activity_name, method in self.CLASS[class_nm]:
                if "init" in activity_name and activity_name in self.NODES and activity_name not in seen:
                    # no calling method, continue traversing from the constructor of the methods class
                    seen.add(activity_name)
                    result += self.traverse(apk, vuln, self.NODES[activity_name], seen)
                elif activity_name in seen:
                    result += self.result_with_tag_from_manifest(apk, vuln, activity_name)
                # other cases, not seen?
        else:
            for parent in node.parents:
                p_node = self.NODES[parent]
                result += self.traverse(apk, vuln, p_node, seen)

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
            method_name = self.find("\.method(.*)", method).split()[-1] # ?
            key = "%s->%s" % (class_name, method_name)

            # add constructor (init) to possibly vulnerable methods if trustmanager is implemented
            if trustmanager and "init" in method_name:
                # add key to TM
                self.VULN.append((key, 'TrustManager'))
            # add constructor (init) to possibly vulnerable methods if hostnameverifier is implemented
            elif hostnameverifier and "init" in method_name:
                self.VULN.append((key, 'HostnameVerifier'))
            elif webviewclient:
                if "init" in method_name:
                    webviewclient_key = key
                elif "onReceivedSslError" in method_name:
                    on_received_ssl_error = True

            self.METHODS.add(key)
            meth_arr.append((key, method))

        # add constructor (init) to possibly vulnerable methods if
        # webviewclient is extended and onReceivedSslError overwritten
        if on_received_ssl_error and webviewclient_key:
            self.VULN.append((webviewclient_key, 'WebViewClient'))

        self.CLASS[class_name] = meth_arr

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

    # Analyses the decoded APK in the given path and returns a list of ???
    def analyze_statically(self, apk_path, apk_filename):
        package, min_sdk_version, target_sdk_version = self.parse_manifest(apk_path)
        self.process_apk(apk_path)

        results = list()

        for vuln in set(self.VULN):
            node = self.NODES[vuln[0]]
            results += self.traverse(apk_path, vuln, node, set())

        results = list(set(results))  # eliminate duplicates

        return StaticAnalysisResults(apk_filename, package, min_sdk_version, target_sdk_version, results)
