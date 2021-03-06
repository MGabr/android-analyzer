import logging
import re
from xml.dom import minidom

from androguard.core.bytecodes.apk import AXMLPrinter

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

    def __init__(self, apk_analysis):
        self.apk = apk_analysis.apk_name

        # reuse existing androguard setup from APKAnalysis for better performance
        self.a = apk_analysis.a
        self.d = apk_analysis.d
        self.dx = apk_analysis.dx
        self.gx = apk_analysis.gx

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

        if not hex_codes:
            return False

        # Cross check the list of hex codes with R$layout to retrieve XML layout file name
        for layout in self.rlayouts:
            for field in layout.get_fields():
                if hex(field.get_init_value().get_value()) in hex_codes:
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
            type_changed = False
            if text_field.tainted_field:
                for path in text_field.tainted_field.get_paths():
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

                                # go down the iter till we reach an invoke-static with the same register
                                while True:
                                    try:
                                        i = next(bc_iter)
                                        if i.get_name() == "invoke-static" and reg_to_follow in i.get_output() \
                                                and "parse" in i.get_output():
                                            new_type = get_type(i)
                                            if text_field.type != new_type:
                                                if type_changed:
                                                    logger.warn(
                                                        "Inferred conflicting xml and implicit type for field %s: %s and %s"
                                                        % text_field.name, text_field.type, new_type)
                                                else:
                                                    logger.warn(
                                                        "Inferred conflicting implicit types for field %s: %s and %s"
                                                        % text_field.name, text_field.type, new_type)
                                            text_field.type = new_type
                                            type_changed = True
                                            break
                                    except StopIteration:
                                        logger.warn("Could not infer implicit type for field %s: No parse invocation"
                                                    % text_field.name)
                                        break

                            idx += i.get_length()

                if not type_changed:
                    logger.warn("Could not infer implicit type for field %s" % text_field.name)

    # Return a dict of the class names and the classes
    def get_class_dict(self):
        classes = {}
        for clazz in self.d.get_classes():
            # get the name for using as key
            clazz_name = re.search("L(.*);", clazz.get_name()).group(1).replace("/", ".")
            classes[clazz_name] = clazz

        return classes

    def get_input_field_from_code(self, class_object, field, class_fields):
        logger.debug("analyzing field %s" % field)
        for method in class_object.get_methods():
            inst_iter = iter(method.get_instructions())
            for i in inst_iter:
                if ("const" == i.get_name() or "const/high16" == i.get_name()) and field == parse_const(i):
                    # get the register in which the constant is assigned
                    register = i.get_output().split(',')[0].strip()

                    while True:
                        try:
                            last_i = i
                            i = next(inst_iter)
                        except StopIteration:
                            logger.warn("Could not get input field %s from code" % field)
                            return

                        # follow the register to the next invoke-virtual of findViewById
                        if (register in i.get_output() and "findViewById" in i.get_output()) \
                                and "invoke-virtual" in i.get_name():
                            # and get the register of that output
                            register = i.get_output().split(',')[1].strip()

                        elif i.get_name() == "move-result-object" and "invoke-virtual" in last_i.get_name():
                            register = i.get_output().strip()

                        elif i.get_name() == "iput-object" and register in i.get_output().split(',')[0].strip():
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

        self.type_class = self.get_type_class()
        self.type_variation = self.get_type_variation(self.type_class)

    type_mask_class= 0x0000000f
    #TODO add more types
    type_class_lookup = {
        0x00000000: 'TYPE_NULL',
        0x00000001: 'TYPE_CLASS_TEXT',
        0x00000002: 'TYPE_CLASS_NUMBER',
        0x00000003: 'TYPE_CLASS_PHONE',
        0x00000004: 'TYPE_CLASS_DATETIME'
    }

    def get_type_class(self):
        type_class = int(self.type, 16) & self.type_mask_class
        if type_class in self.type_class_lookup:
            return self.type_class_lookup[type_class]
        else:
            return "TYPE_CLASS_NOT_RECOGNIZED"

    type_mask_variation = 0x00000ff0
    type_variation_lookup = {
        'TYPE_NULL': {

        },
        'TYPE_CLASS_TEXT': {
            0x00: 'TYPE_TEXT_VARIATION_NORMAL',
            0x10: 'TYPE_TEXT_VARIATION_URI',
            0x20: 'TYPE_TEXT_VARIATION_EMAIL_ADDRESS',
            0x30: 'TYPE_TEXT_VARIATION_EMAIL_SUBJECT',
            0x40: 'TYPE_TEXT_VARIATION_SHORT_MESSAGE',
            0x50: 'TYPE_TEXT_VARIATION_LONG_MESSAGE',
            0x60: 'TYPE_TEXT_VARIATION_PERSON_NAME',
            0x70: 'TYPE_TEXT_VARIATION_POSTAL_ADDRESS',
            0x80: 'TYPE_TEXT_VARIATION_PASSWORD',
            0x90: 'TYPE_TEXT_VARIATION_VISIBLE_PASSWORD',
            0xa0: 'TYPE_TEXT_VARIATION_WEB_EDIT_TEXT',
            0xb0: 'TYPE_TEXT_VARIATION_FILTER',
            0xc0: 'TYPE_TEXT_VARIATION_PHONETIC',
            0xd0: 'TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS',
            0xe0: 'TYPE_TEXT_VARIATION_WEB_PASSWORD'
        },
        'TYPE_CLASS_NUMBER': {
            0x00: 'TYPE_NUMBER_VARIATION_NORMAL',
            0x10: 'TYPE_NUMBER_VARIATION_PASSWORD'
        },
        'TYPE_CLASS_PHONE': {

        },
        'TYPE_CLASS_DATETIME': {
            0x00: 'TYPE_DATETIME_VARIATION_NORMAL',
            0x10: 'TYPE_DATETIME_VARIATION_DATE',
            0x20: 'TYPE_DATETIME_VARIATION_TIME'
        }
    }

    def get_type_variation(self, type_class):
        type_variation = int(self.type, 16) & self.type_mask_variation
        if type_class in self.type_variation_lookup and type_variation in self.type_variation_lookup[type_class]:
            return self.type_variation_lookup[type_class][type_variation]
        else:
            return ''

    def __json__(self):
        return {
            'name': self.name,
            'type_class': self.type_class,
            'type_variation': self.type_variation}

    def __str__(self):
        type_class = self.get_type_class()
        type_var = self.get_type_variation(type_class)
        return 'name: %s;id: %s;type: %s;variations: %s;' % (self.name, self.id, type_class, type_var)
