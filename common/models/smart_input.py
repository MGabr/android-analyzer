from sqlalchemy import Column, String, JSON

from common.db_base import Base


class SmartInputResult(Base):
    __tablename__ = 'smartinputresult'
    apk_filename = Column(String(2048), primary_key=True)
    result = Column(JSON())


class SmartInputAssignment:
    def __init__(self):
        self.type_class_ass = {
            'TYPE_NULL': '',
            'TYPE_CLASS_TEXT': '',
            'TYPE_CLASS_NUMBER': '',
            'TYPE_CLASS_PHONE': '',
            'TYPE_CLASS_DATETIME': ''
        }
        self.type_variation_ass = {
            'TYPE_TEXT_VARIATION_NORMAL': 'example',
            'TYPE_TEXT_VARIATION_URI': 'https://www.amazon.com',
            'TYPE_TEXT_VARIATION_EMAIL_ADDRESS': 'example@example.com',
            'TYPE_TEXT_VARIATION_EMAIL_SUBJECT': 'Example Email Subject',
            'TYPE_TEXT_VARIATION_SHORT_MESSAGE': 'Example short message',
            'TYPE_TEXT_VARIATION_LONG_MESSAGE': 'Example long message, example long message. Example long message.',
            'TYPE_TEXT_VARIATION_PERSON_NAME': 'Examplename',
            'TYPE_TEXT_VARIATION_POSTAL_ADDRESS': '',
            'TYPE_TEXT_VARIATION_PASSWORD': 'pass123:',
            'TYPE_TEXT_VARIATION_VISIBLE_PASSWORD': 'pass123;',
            'TYPE_TEXT_VARIATION_WEB_EDIT_TEXT': '',
            'TYPE_TEXT_VARIATION_FILTER': '',
            'TYPE_TEXT_VARIATION_PHONETIC': '',
            'TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS': 'example@example.com',
            'TYPE_TEXT_VARIATION_WEB_PASSWORD': 'pass123:',

            'TYPE_NUMBER_VARIATION_NORMAL': '12',
            'TYPE_NUMBER_VARIATION_PASSWORD': '1234',

            'TYPE_DATETIME_VARIATION_NORMAL': '',
            'TYPE_DATETIME_VARIATION_DATE': '',
            'TYPE_DATETIME_VARIATION_TIME': ''
        }

    def __json__(self):
        return {'type_class_ass': self.type_class_ass, 'type_variation_ass': self.type_variation_ass}
