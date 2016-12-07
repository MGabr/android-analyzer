from androguard.core.analysis.analysis import VMAnalysis
from androguard.core.analysis.ganalysis import GVMAnalysis
from androguard.core.bytecodes.apk import APK, AXMLPrinter
from androguard.core.bytecodes.dvm import DalvikVMFormat
from xml.dom import minidom
import re
import logging


logging.basicConfig(level=logging.DEBUG, filename="log.txt")
logger = logging.getLogger(__name__)


# populate fields with field id and name pairs
# populate field_refs with field id and field reference pairs
def get_fields(rids):
    fields = {}
    field_refs = {}
    for rid in rids:
        for f in rid.get_fields():
            id = hex(f.get_init_value().get_value())
            fields[id] = f.get_name()
            field_refs[id] = f
    return fields, field_refs


# Return a dict of the field names and the fields
def get_class_fields(clazz):
    class_fields = {}
    for f in clazz.get_fields():
        class_fields[f.get_name()] = f
    return class_fields


def get_type(i):
    # TODO add more cases
    if i.get_output().endswith("F"):
        return 'float'
    elif i.get_output().endswith("I"):
        return 'integer'
    elif i.get_output().endswith("B"):
        return 'byte'
    elif i.get_output().endswith("S"):
        return 'short'
    elif i.get_output().endswith("C"):
        return 'char'
    elif i.get_output().endswith("J"):
        return 'long'
    elif i.get_output().endswith("D"):
        return 'double'
    elif i.get_output().endswith("V"):
        return 'void'


def parse_const(instruction):
    if instruction.get_name() == "const":
        return hex(instruction.get_literals().pop())
    elif instruction.get_name() == "const/high16":
        return hex(instruction.get_literals().pop()) + "0" * 4
    else:
        raise Exception("Unrecognized instruction: " + instruction.get_name())


class GetFieldType:

    def __init__(self, apk_name):
        self.apk = "input_apks/" + apk_name + ".apk"

        logger.debug("Analyzing " + self.apk)

        # analyze the dex file
        self.a = APK(self.apk)

        # get the vm analysis
        self.d = DalvikVMFormat(self.a.get_dex())
        self.dx = VMAnalysis(self.d)
        self.gx = GVMAnalysis(self.dx, None)

        self.d.set_vmanalysis(self.dx)
        self.d.set_gvmanalysis(self.gx)

        # create the cross reference
        self.d.create_xref()
        self.d.create_dref()

        try:
            self.classes = self.get_class_dict()  # Get the classes for this apk
            self.rlayouts = self.get_rlayouts(self.d.get_classes())  # Find the R$layout classes
            self.rids = self.get_rids(self.d.get_classes())  # Find the R$id classes
            self.fields, self.field_refs = get_fields(self.rids)  # Store all fields referenced in R$id
        except Exception, e:
            logger.error(e)

    # Get R$id classes
    def get_rids(self, classes):
        rids = []
        for c in classes:
            if "R$id" in c.get_name():
                logger.debug("Found R$id class at " + c.get_name())
                rids.append(c)
        if len(rids) > 0:
            return rids
        raise Exception("R$id not found. apk=" + self.apk)

    # Get R$layout classes
    def get_rlayouts(self, classes):
        layouts = []
        for c in classes:
            if "R$layout" in c.get_name():
                logger.debug("Found R$layout class at " + c.get_name())
                layouts.append(c)
        if len(layouts) > 0:
            return layouts
        raise Exception("R$layout not found. apk=" + self.apk)

    # Return every instance of an EditText field and their inputType in the XML.
    # Not all EditText fields will have an inputType specified in the XML.
    # (That's why we use code inspection later).
    def get_input_fields_with_input_types_from_xml(self, xml):
        input_fields = {}
        activity = self.get_xml(xml)
        for item in activity.getElementsByTagName("EditText"):
            android_id = None
            input_type = None
            for k, v in item.attributes.itemsNS():
                if k[1] == u'id':
                    android_id = v[1:]
                if k[1] == u'inputType':
                    input_type = v

            if android_id:
                id = hex(int(android_id, 16))
                input_fields[id] = input_type

        return input_fields

    def get_xml(self, fil):
        ap = AXMLPrinter(self.a.get_file(fil))
        buff = minidom.parseString(ap.get_buff())

        return buff

    # TODO: multiple layouts for activity?
    def get_activity_xml(self, activity):
        # Build an list of every layout hex value referenced in activity bytecodes
        hex_codes = []
        for method in activity.get_methods():
            if method.get_name() == 'onCreate':
                for idx, instruction in enumerate(method.get_instructions()):
                    # Find setContentView, then parse the passed value from the
                    # previous const or const/high16 instruction
                    if "setContentView" in instruction.show_buff(0):
                        instruction = method.get_code().get_bc().get_instruction(idx-1)
                        if "const" in instruction.get_name():
                            hex_codes.append(parse_const(instruction))
                        elif "move" in instruction.get_name():
                            hex_codes.append(self.parse_move(method.get_code().get_bc(), idx - 1))

        logger.debug("hex codes " + str(hex_codes))
        if not hex_codes:
            return False

        # Cross check the list of hex codes with R$layout to retrieve XML layout file name
        for layout in self.rlayouts:
            for field in layout.get_fields():
                if hex(field.get_init_value().get_value()) in hex_codes:
                    logger.debug("xml name " + field.get_name())
                    return 'res/layout/%s.xml' % field.get_name()
                    # TODO: do we also have to consider other layout versions, e.g. layout-v17 and layout-v21

        raise Exception("XML not found" + str(hex_codes))

    def parse_move(self, bc, idx):
        i = bc.get_instruction(idx)
        try:
            register = i.get_output().split(',')[1].strip()
        except IndexError:
            raise Exception(self.apk)
        for x in range(idx - 1, -1, -1):
            i = bc.get_instruction(x)
            if "const" in i.get_name() and register in i.get_output():
                return parse_const(bc.get_instruction(x))

    def infer_implicit_input_types(self, text_fields):
        for text_field in text_fields:
            for path in text_field.tainted_field.get_paths():
                logger.debug("path " + str(path))
                access, field_id = path[0]

                # get the method id
                m_idx = path[1]

                if access == "R":
                    # get the method object from the vm
                    method = self.d.get_method_by_idx(m_idx)
                    code = method.get_code()
                    bc = code.get_bc()

                    idx = 0
                    bc_iter = iter(bc.get_instructions())
                    for i in bc_iter:
                        if field_id == idx:
                            # get the register for the iget-object
                            reg_to_follow = i.get_output().split(',')[0].strip()
                            logger.debug("reg_to_follow " + str(reg_to_follow))

                            # go down the iter till we reach an invoke-static with the same register
                            while True:
                                try:
                                    i = next(bc_iter)
                                    if i.get_name() == "invoke-static" and reg_to_follow in i.get_output() \
                                            and "parse" in i.get_output():
                                        text_field.type = get_type(i)
                                        logger.debug("text field changed to " + str(get_type()))
                                        break
                                except StopIteration:
                                    break

                        idx += i.get_length()

    # Return a dict of the class names and the classes
    def get_class_dict(self):
        classes = {}
        for clazz in self.d.get_classes():
            # get the name for using as key
            clazz_name = re.search("L(.*);", clazz.get_name()).group(1).replace("/", ".")
            classes[clazz_name] = clazz

        return classes

    def get_input_field_from_code(self, class_object, field, class_fields):
        logger.debug("analyzing field %s" % field) #
        for method in class_object.get_methods():
            logger.debug("method " + str(method))
            inst_iter = iter(method.get_instructions())
            for i in inst_iter:
                logger.debug("i " + str(i))
                if "const" == i.get_name() or "const/high16" == i.get_name():
                    logger.debug("field " + str(field) + ", parse_const " + str(parse_const(i)))
                if ("const" == i.get_name() or "const/high16" == i.get_name()) and field == parse_const(i):
                    # get the register in which the constant is assigned
                    register = i.get_output().split(',')[0].strip()
                    logger.debug("const register " + str(register))

                    while True:
                        try:
                            i = next(inst_iter)
                        except StopIteration:
                            return

                        # follow the register to the next invoke-virtual of findViewById
                        if (register in i.get_output() and "findViewById" in i.get_output()) \
                                and "invoke-virtual" in i.get_name():
                            # and get the register of that output
                            register = i.get_output().split(',')[1].strip()
                            logger.debug("register " + str(register))

                        if i.get_name() == "move-result-object" and register in i.get_output():
                            logger.debug(str(i.get_name()) + ";- output " + str(i.get_output()) + ";- name " + str(method.get_name()))
                            register = i.get_output().strip()
                            logger.debug("register " + str(register))

                        if i.get_name() == "iput-object":
                            logger.debug(str(i.get_name()) + ";- output " + str(i.get_output()) + ";- name " + str(method.get_name()))
                            # example: v2, v5, Lcom/example/markus/acceptallcertificatestestapp/MainActivity;->editText
                            # Landroid/widget/EditText;
                            out_sp = re.search(r".*, (.*)->(\b[\w]*\b) (.*)", i.get_output()).groups()

                            # now get the field from the class object
                            tainted_field = self.dx.get_tainted_field(out_sp[0], out_sp[1], out_sp[2])

                            class_field = class_fields[out_sp[1]]

                            return tainted_field, class_field

    def analyze(self):
        smart_input_results = dict()
        try:
            for clazz in self.a.get_activities():
                try:
                    logger.debug("analyzing activity %s" % clazz)

                    if clazz in self.classes:
                        class_object = self.classes[clazz]

                        # Find all XML layouts referenced in setContentView in activity bytecodes
                        activity_xml = self.get_activity_xml(class_object)
                        if not activity_xml:
                            logger.warn("No XML's found in %s" % clazz)
                            continue
                        input_types_for_fields = self.get_input_fields_with_input_types_from_xml(activity_xml)

                        class_fields = get_class_fields(class_object)

                        # Combine all information into a TextField array
                        text_fields = []
                        for f in input_types_for_fields:
                            instance_ref = self.get_input_field_from_code(class_object, f, class_fields)
                            if instance_ref:
                                tainted_field, class_field = instance_ref
                                tf = TextField(f, self.fields[f], input_types_for_fields[f], self.field_refs[f],
                                               tainted_field, class_field)
                            else:
                                tf = TextField(f, self.fields[f], input_types_for_fields[f], self.field_refs[f])
                            text_fields.append(tf)

                        if not text_fields:
                            logger.warn("No text fields found in %s" % activity_xml)
                        else:
                            self.infer_implicit_input_types(text_fields)
                            smart_input_results[clazz] = text_fields

                except Exception, e:
                    logger.error(e)

            if len(smart_input_results) > 0:
                logger.debug("%i text fields identified in %s" % (len(smart_input_results), self.apk))

        except Exception, e:
            logger.error(e)
            if len(smart_input_results) > 0:
                logger.debug("%i text fields identified in %s" % (len(smart_input_results), self.apk))

        return smart_input_results


class TextField:

    def __init__(self, id, name, type, reference, tainted_field=None, class_field=None):
        self.id = id
        self.name = name
        self.type = type
        self.ref = reference
        self.tainted_field = tainted_field
        self.class_field = class_field

    def get_id(self, in_hex=True):
        if in_hex:
            return hex(self.id)
        else:
            return int(self.id)

    #TODO add more types
    type_class_lookup = {
        u'0x00000000': 'TYPE_NULL',
        u'0x00000001': 'TYPE_CLASS_TEXT',
        u'0x00000002': 'TYPE_CLASS_NUMBER',
        u'0x00000003': 'TYPE_CLASS_PHONE',
        u'0x00000004': 'TYPE_CLASS_DATETIME',
        u'0x00000081': 'textPassword',
        u'0x00000021': 'textEmailAddress',
    }

    def get_type_class(self):
        if self.type in self.type_class_lookup:
            return self.type_class_lookup[self.type]
        else:
            return "TYPE_CLASS_NOT_RECOGNIZED"

    type_variation_lookup = {
        'TYPE_NULL': {

        },
        'TYPE_CLASS_TEXT': {
            '0x0': 'TYPE_TEXT_VARIATION_NORMAL',
            '0x1': 'TYPE_TEXT_VARIATION_URI',
            '0x2': 'TYPE_TEXT_VARIATION_EMAIL_ADDRESS',
            '0x3': 'TYPE_TEXT_VARIATION_EMAIL_SUBJECT',
            '0x4': 'TYPE_TEXT_VARIATION_SHORT_MESSAGE',
            '0x5': 'TYPE_TEXT_VARIATION_LONG_MESSAGE',
            '0x6': 'TYPE_TEXT_VARIATION_PERSON_NAME',
            '0x7': 'TYPE_TEXT_VARIATION_POSTAL_ADDRESS',
            '0x8': 'TYPE_TEXT_VARIATION_PASSWORD',
            '0x9': 'TYPE_TEXT_VARIATION_VISIBLE_PASSWORD',
            '0xa': 'TYPE_TEXT_VARIATION_WEB_EDIT_TEXT',
            '0xb': 'TYPE_TEXT_VARIATION_FILTER',
            '0xc': 'TYPE_TEXT_VARIATION_PHONETIC',
            '0xd': 'TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS',
            '0xe': 'TYPE_TEXT_VARIATION_WEB_PASSWORD'
        },
        'TYPE_CLASS_NUMBER': {
            '0x0': 'TYPE_NUMBER_VARIATION_NORMAL',
            '0x1': 'TYPE_NUMBER_VARIATION_PASSWORD'
        },
        'TYPE_CLASS_PHONE': {

        },
        'TYPE_CLASS_DATETIME': {
            '0x0': 'TYPE_DATETIME_VARIATION_NORMAL',
            '0x1': 'TYPE_DATETIME_VARIATION_DATE',
            '0x2': 'TYPE_DATETIME_VARIATION_TIME'
        }
    }

    def get_type_variation(self, type_class):
        try:
            type_int = int(self.type, 16)
            type_hex = hex((type_int / 16) % 256)
            return self.type_variation_lookup[type_class][type_hex]
        except Exception:
            return ''

    def get_type_flags(self, type_class):
        return []

    def __str__(self):
        type_class = self.get_type_class()
        type_var = self.get_type_variation(type_class)
        type_flags = ', '.join(self.get_type_flags(type_class))
        return 'name: %s;id: %s;type: %s;variations: %s;flags: %s;' % (
            self.name, self.id, type_class, type_var, type_flags)


def generate_smart_input(apk_name):
    smart_input_results = GetFieldType(apk_name).analyze()
    return smart_input_results

if __name__ == '__main__':
    generate_smart_input("acceptallcertificates-release")
