# this config extractor can only work with QuasarRAT with version 1.3.0.0
import sys
import os
from pathlib import Path
from re import search, DOTALL, findall
import ast
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
    
class QuasarRATParser:
    # regex to find the ldstr opcodes and 4 bytes after them, stsfld opcode and 4 bytes after them.
    PATTERN_CONFIG_START = b"\x72(.{4})\x80(.{4})"
    # pattern to find the start of the metadata table
    PATTERN_CLR_METADATA_START = b"\x42\x53\x4a\x42"
    # metadata tables list and their row size (each row size differentiates for each sample)
    MAP_TABLE = {
        'Module': {
        'row_size': 12
        },
        'TypeRef': {
            'row_size': 10
        },
        'TypeDef': {
            'row_size': 18
        },
        'FieldPtr': {
            'row_size': 2
        },
        'Field': {
            'row_size': 8
        },
        'MethodPtr': {
            'row_size': 2
        },
        'Method': {
            'row_size': 16
        },
        'ParamPtr': {
            'row_size': 2
        },
        'Param': {
            'row_size': 8
        },
        'InterfaceImpl': {
            'row_size': 4
        },
        'MemberRef': {
            'row_size': 8
        },
        'Constant': {
            'row_size': 6
        },
        'CustomAttribute': {
            'row_size': 8
        },
        'FieldMarshal': {
            'row_size': 4
        },
        'DeclSecurity': {
            'row_size': 6
        },
        'ClassLayout': {
            'row_size': 8
        },
        'FieldLayout': {
            'row_size': 6
        },
        'StandAloneSig': {
            'row_size': 2
        },
        'EventMap': {
            'row_size': 4
        },
        'EventPtr': {
            'row_size': 2
        },
        'Event': {
            'row_size': 8
        },
        'PropertyMap': {
            'row_size': 4
        },
        'PropertyPtr': {
            'row_size': 2
        },
        'Property': {
            'row_size': 8
        },
        'MethodSemantics': {
            'row_size': 6
        },
        'MethodImpl': {
            'row_size': 6
        },
        'ModuleRef': {
            'row_size': 4
        },
        'TypeSpec': {
            'row_size': 2
        },
        'ImplMap': {
            'row_size': 10
        },
        'FieldRVA': {
            'row_size': 6
        },
        'ENCLog': {},
        'ENCMap': {},
        'Assembly': {},
        'AssemblyProcessor': {},
        'AssemblyOS': {},
        'AssemblyRef': {},
        'AssemblyRefProcessor': {},
        'AssemblyRefOS': {},
        'File': {},
        'ExportedType': {},
        'ManifestResource': {},
        'NestedClass': {},
        'GenericParam': {},
        'MethodSpec': {},
        'GenericParamConstraint': {},
        'Reserved 2D': {},
        'Reserved 2E': {},
        'Reserved 2F': {},
        'Document': {},
        'MethodDebugInformation': {},
        'LocalScope': {},
        'LocalVariable': {},
        'LocalConstant': {},
        'ImportScope': {},
        'StateMachineMethod': {},
        'CustomDebugInformation': {},
        'Reserved 38': {},
        'Reserved 39': {},
        'Reserved 3A': {},
        'Reserved 3B': {},
        'Reserved 3C': {},
        'Reserved 3D': {},
        'Reserved 3E': {},
        'Reserved 3F': {}
    }

    class QuasarRATAESDecryptor:
        # pattern for getting RVA of the AES.Salt variable
        PATTERN_AES_METADATA = b"\x02\x7e(.{4})\x20(.{4})"
        # pattern for getting the AES key and block size
        PATTERN_AES_KEY_AND_BLOCK_SIZE = b"\x08\x20(.{4})\x6F"
        # pattern for field table RVA of the salt initializer (salt initializer initializes a byte array)
        PATTERN_SALT_ARRAY_ID = b"\x1F\x20\x8D.{4}\x25\xD0(.{2})"
        # pattern for getting the passphrase's RVA
        PATTERN_DERIVE_KEY_LDSFLD = b"\x7E(.{4})\x80.{4}\x7E"
        PATTERN_DERIVE_KEY_LDSTR = b"\x72(.{4})\x80.{4}(\x72.{4}\x80.{4}){2}"
            
        def __init__(self, parent_parser):
            self.parent = parent_parser
            self.salt_flag, self.iterations = self.get_aes_metadata()
            self.aes_salt = self.get_salt()
            self.key_size, self.block_size = self.get_key_and_block_size()
            self.aes_key = self.derive_aes_key()
        
        # get the metadata flag of the AES salt and iteration value
        def get_aes_metadata(self):
            metadata_flag = search(self.PATTERN_AES_METADATA, self.parent.data, DOTALL)
            salt_flag = int.from_bytes(metadata_flag.group(1), byteorder="little")
            iterations_byte = search(self.PATTERN_AES_METADATA, self.parent.data, DOTALL)
            iterations = int.from_bytes(metadata_flag.group(2), byteorder="little")
            return salt_flag, iterations
        
        # get salt initialized as a byte array
        def get_salt_rva(self):
            salt_array_id = search(self.PATTERN_SALT_ARRAY_ID, self.parent.data, DOTALL).group(1)
            salt_array_id_int = int.from_bytes(salt_array_id, byteorder="little")
            # go to Field RVA
            field_rva_cursor = self.parent.get_subtable_map("FieldRVA")
            # In the Field RVA, find the relevant row with field value matches with the last three bytes
            rva_value_found = False
            for i in range(self.parent.table_map["FieldRVA"]["row_num"]):
                if int.from_bytes(self.parent.data[field_rva_cursor + 4:field_rva_cursor + 6], byteorder="little") == salt_array_id_int:
                    rva_value = self.parent.data[field_rva_cursor:field_rva_cursor + 4]
                    rva_value_found = True
                    break
                field_rva_cursor += self.parent.table_map["FieldRVA"]["row_size"]
            if not rva_value_found:
                print("FieldRVA value of the AES Salt CANNOT BE FOUND")
                sys.exit(7)
            rva_value_int = int.from_bytes(rva_value, byteorder="little")
            return rva_value_int
        
        # get the offset of rva
        def rva_to_file_offset(self, rva_value):
            text_section_start = self.parent.data.find(b".text")
            va_pointer = int.from_bytes(self.parent.data[text_section_start + 12:text_section_start + 16], byteorder="little")
            file_offset = int.from_bytes(self.parent.data[text_section_start + 20:text_section_start + 24], byteorder="little")
            result = rva_value - va_pointer + file_offset
            return result
            
        # get salt value
        def get_salt(self):
            salt_offset = self.rva_to_file_offset(self.get_salt_rva())
            salt = b"0"
            for i in range(32):
                salt_item = self.parent.data[salt_offset + i]
                salt += salt_item.to_bytes(1, byteorder="big")
            return salt[1:]
        
        # get the AES key and block size
        def get_key_and_block_size(self):
            key_size_byte = findall(self.PATTERN_AES_KEY_AND_BLOCK_SIZE, self.parent.data, DOTALL)[0]
            block_size_byte = findall(self.PATTERN_AES_KEY_AND_BLOCK_SIZE, self.parent.data, DOTALL)[1]
            key_size = int.from_bytes(key_size_byte, byteorder="little") // 8
            block_size = int.from_bytes(block_size_byte, byteorder="little")
            return key_size, block_size
        
        # get aes passphrase
        def get_aes_passphrase(self):
            config_map = self.parent.config_map
            try:
                passphrase_rva = search(self.PATTERN_DERIVE_KEY_LDSFLD, self.parent.data, DOTALL).group(1)
                for config in config_map:
                    if config[0] == hex(int.from_bytes(passphrase_rva, byteorder="little")):
                         return config[2]
            except:
                passphrase_rva = search(self.PATTERN_DERIVE_KEY_LDSTR, self.parent.data, DOTALL).group(1)
                config_addr_map = self.parent.config_addr_map
                for config in config_addr_map:
                    if config[0] == hex(int.from_bytes(passphrase_rva, byteorder="little")):
                        hold_strings_rva = config[1]
                for config in config_map:
                    if config[0] == hold_strings_rva:
                         return config[2]
                    
            
        def derive_aes_key(self):
            passphrase = self.get_aes_passphrase()
            new_passphrase = ""
            for byte in passphrase:
                if byte != 0:
                    new_passphrase += str(chr(byte))
            new_passphrase = bytes(new_passphrase.encode("utf-8"))
            kdf = PBKDF2HMAC(SHA1(), length=self.key_size, salt=self.aes_salt, iterations=self.iterations)
            aes_key = kdf.derive(new_passphrase)
            return aes_key
            
        def decrypt(self, iv, ciphertext):
            aes_cipher = Cipher(AES(self.aes_key), CBC(iv), backend=default_backend())
            decryptor = aes_cipher.decryptor()
            unpadder = PKCS7(self.block_size).unpadder()
            padded_text = decryptor.update(ciphertext) + decryptor.finalize()
            unpadded_text = unpadder.update(padded_text) + unpadder.finalize()
            return unpadded_text
        
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = self.get_file_data()
        self.config_addr_map = self.get_config_addr_map()
        self.table_map = self.get_table_map()
        self.strings_stream_rva, self.variable_name = self.get_strings_name()
        self.variable_value = self.get_US_name()
        self.config_map = self.get_config_map()
        self.aes_decryptor = self.QuasarRATAESDecryptor(self)
        self.config = self.decrypt_config()
    
    # read the file binary data
    def get_file_data(self):
        try:
            with open(self.file_path, "rb") as fp:
               data = fp.read() 
        except FileNotFoundError as e:
            print(f"ERROR: File {self.file_path} cannot be found.")
            sys.exit(2)
        return data
        
    # get where the config values are loaded
    def get_config_addr_map(self):
        # search the regex through the binary
        hit = findall(self.PATTERN_CONFIG_START, self.data, DOTALL)
        if hit is None:
            print("CANNOT FIND THE CONFIG PATTERN")
            sys.exit(3)

        # convert the byte values to hex
        strings_offset_list = []
        for us_rva, strings_rva in hit:
            us_rva2 = hex(int.from_bytes(us_rva, byteorder="little"))
            strings_rva2 = hex(int.from_bytes(strings_rva, byteorder="little"))
            strings_offset_list.append((us_rva2, strings_rva2))
        return strings_offset_list

    # get the start of the metadata (Store Signature). This is where the metadata table begins
    def get_metadata_header_offset(self):
        metadata_start = self.data.find(self.PATTERN_CLR_METADATA_START)
        if metadata_start == -1:
            print("CANNOT FIND THE METADATA STARTING OFFSET")
            sys.exit(4)
        return metadata_start
    
    # get the start of the #~ stream 
    def get_stream_start(self, stream_id):
        # get the relative address of the stream #~
        stream_offset_bin = self.data.find(stream_id)
        if stream_offset_bin == -1:
            print(f"CANNOT FIND STREAM {stream_id} OFFSET")
            sys.exit(5)

        # convert the address written 8 bytes before and it's 4 bytes long into integer
        stream_offset = int.from_bytes(self.data[stream_offset_bin-8:stream_offset_bin-4], byteorder="little")

        # to get the actual address of the next table, add the relative address to the start of the metadata table
        return stream_offset + self.get_metadata_header_offset()

    # get the mask_valid value so that we can map the metadata stream
    def get_mask_valid(self):
        # mask_valid is 8 bytes ahead of the table it's in
        mask_valid_addr = self.get_stream_start(b"#~") + 8
        # mask_valid value is 8 bytes long
        mask_valid = int.from_bytes(self.data[mask_valid_addr:mask_valid_addr+8], byteorder="little")
        return mask_valid
        
    # map the table with its row number, row size and whether they are contained
    def get_table_map(self):
        mask_valid = self.get_mask_valid()
        table_map = self.MAP_TABLE.copy()
        storage_stream_offset = self.get_stream_start(b"#~")
        table_start = storage_stream_offset + 24
        cur_offset = table_start
        try:
            for table in table_map:
                if mask_valid & 2**list(table_map.keys()).index(table):
                    row_count = int.from_bytes(self.data[cur_offset:cur_offset + 4], byteorder="little")
                    table_map[table]["row_num"] = row_count
                    cur_offset += 4
                else:
                    table_map[table]["row_num"] = 0
        except:
            print("CANNOT GET TABLE MAP")
            sys.exit(6)
        return table_map
    
    # get the offset where the fields table starts
    def get_subtable_map(self, table_name):
        storage_stream_offset = self.get_stream_start(b"#~")
        table_cursor = storage_stream_offset + 24
        field_start = 0
        temp_cursor = 0
        field_found = False
        for table in self.table_map:
            if self.table_map[table]["row_num"] == 0:
                continue
            else:
                table_cursor += 4
            
            if table == table_name:
                field_found = True
            elif not field_found:
                table_cursor += self.table_map[table]["row_num"] * self.table_map[table]["row_size"]
            field_start = table_cursor

        return field_start
    
    # iterate over the fields table and get the offset of names which is RVA in #Strings stream
    def get_offset_from_fields(self):
        field_start = self.get_subtable_map("Field")
        string_field_name = []
        for config_us_rva, config_strings_rva in self.config_addr_map:
            string_row_start = field_start + (int(config_strings_rva[-3:], 16) - 1) * 8
            string_field_name.append(int.from_bytes(self.data[string_row_start + 2:string_row_start + 6], byteorder="little"))
        return string_field_name

    # look at the #strings stream and get the variable name
    def get_strings_name(self):
        strings_start = self.get_stream_start(b"#Strings")
        variable_list = []
        variable_fields_rva = []
        for name in self.get_offset_from_fields():
            variable_list.append(self.data[strings_start + name:strings_start + name + 100].partition(b"\0")[0])
        for config_us_rva, config_strings_rva in self.config_addr_map:
            variable_fields_rva.append(config_strings_rva)
        return variable_fields_rva, variable_list
    
    # extract the decrypted user strings from #US stream
    def get_US_name(self):
        us_start = self.get_stream_start(b"#US")
        config_value = []
        for us_rva, strings_rva in self.config_addr_map:
            config_value.append(self.data[us_start + int(us_rva[-4:], 16) + 1:].partition(b"\x00\x00")[0])
        return config_value

    # concatanate variable name RVA, variable name and variable value into a triple
    def get_config_map(self):
        config_list = []
        for i in range(len(self.variable_value)):
            config_list.append((self.strings_stream_rva[i], self.variable_name[i], self.variable_value[i]))
        return config_list

    def decrypt_config(self):
        decrypted_config = {}
        for rva, key, val in self.config_map:
            try:
                decoded_val = b64decode(val)
                iv = decoded_val[32:48]
                ciphertext = decoded_val[48:]
                decrypted_config[key] = self.aes_decryptor.decrypt(iv, ciphertext)
                #print(decrypted_config[key])
            except:
                continue
        return decrypted_config
     
    def report(self):
        report_dict = {}
        variable_name_list = ["VERSION:","HOSTS:","SUBDIRECTORY:","INSTALL_NAME:","MUTEX:","STARTUP_NAME:","TAG:","LOG_FOLDER:"]
        counter = 0
        for config in self.config:
            report_dict[counter] = self.config[config]
            counter += 1
        for i in range(counter):
            print(variable_name_list[i], report_dict[i])
            
    
def main():
    arg = sys.argv[1]
    abs_fp = os.path.abspath(arg)
    file_path_obj = Path(abs_fp)
    
    file_paths = []
    if not file_path_obj.exists():
        print(f"FILE {arg} DOES NOT EXISTS")
        sys.exit(1)
    elif file_path_obj.is_file():
        print(QuasarRATParser(abs_fp).report())
    else:
        os.chdir(abs_fp)
        for file_path in os.listdir(Path.cwd()):
            print(QuasarRATParser(file_path).report())

if __name__ == "__main__":
    main()
