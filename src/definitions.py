import os


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))[:-len("src")]
FILES_DIR = ROOT_DIR + 'files/'
CERTS_DIR = FILES_DIR + 'certs/'
TMP_FILES_DIR = FILES_DIR + 'tmp/'
INPUT_APK_DIR = TMP_FILES_DIR + 'input_apks/'
DECODED_APK_DIR = TMP_FILES_DIR + 'decoded_apks/'
LOGS_DIR = TMP_FILES_DIR + 'logs/'
