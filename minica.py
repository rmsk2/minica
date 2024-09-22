#!/usr/bin/python3

import sys
import getpass
import os
import os.path
import configparser
import pathlib
import traceback
import argparse
import shutil

ERR_OK = 0
ERR_NOT_OK = 100

SEC_TYPE_CA = "CA"
SEC_TYPE_P12 = "PKCS#12"


# Change this to suit your needs
###############################################
CA_KEY_BITS = 4096
SERVER_KEY_BITS = 3072
CLIENT_KEY_BITS = 3072
MAIL_KEY_BITS = 3072
END_ENTITY_VALID_DAYS = 365
ROOT_VALID_YEARS = 5
CRL_VALID_DAYS = 30
DEFAULT_COUNTRY = 'DE'
DEFAULT_OU = 'Wohnzimmer'
DEFAULT_HASH = 'sha256'
CA_BASE_DIR = './SSL-CA/'
CDP_URL = 'http://test/ca/crl.crl'
###############################################


CA_HOME_DIRECTORY = pathlib.Path(CA_BASE_DIR)


class SSLCAException(Exception):
    def __init__(self, args):
        Exception.__init__(self, args)    


class INIFile:
    def __init__(self, section_list = None):
        if section_list == None:
            section_list = []
        
        self.__sections = section_list
    
    def __write_section(self, section, file):
        sect_name, data = section
        string_data = ''
        
        if sect_name != None:
            string_data += f'[ {sect_name} ]\n'
        
        for i in data:
            string_data += f'{i[0]} = {i[1]}\n'
        
        string_data += '\n'
        
        file.write(string_data.encode('ascii'))
    
    def add_section(self, section):
        self.__sections.append(section)
    
    def set_sections(self, section_list):
        self.__sections = section_list
    
    @staticmethod
    def get_std_sections(ca_name):
        ini = INIFile([])
        
        ca_section = []
        ca_section.append(('dir', CA_HOME_DIRECTORY / ca_name))
        ca_section.append(('new_certs_dir','$dir/certs'))
        ca_section.append(('crl_dir', '$dir/crls'))
        ca_section.append(('database', '$dir/private/index.txt'))
        ca_section.append(('certificate', '$dir/private/CAcert.pem'))
        ca_section.append(('serial', '$dir/private/serial.txt'))
        ca_section.append(('crl', '$dir/crls/crl.pem'))
        ca_section.append(('crlnumber','$dir/crls/crlnumber.txt'))
        ca_section.append(('crl_extensions', 'crl_ext'))
        ca_section.append(('private_key', '$dir/private/CAkey.pem'))
        ca_section.append(('RANDFILE', '$dir/private/.rand'))
        ca_section.append(('default_days', END_ENTITY_VALID_DAYS))
        ca_section.append(('default_crl_days', CRL_VALID_DAYS))
        ca_section.append(('default_md', DEFAULT_HASH))
        ca_section.append(('unique_subject', 'no'))
        ca_section.append(('preserve', 'no'))
        ca_section.append(('policy', 'policy_std'))
        ini.add_section(('CA_default', ca_section))
        
        policy_section = []
        policy_section.append(('countryName', 'match'))
        policy_section.append(('organizationName', 'match'))
        policy_section.append(('commonName', 'supplied'))
        policy_section.append(('emailAddress', 'optional'))
        policy_section.append(('organizationalUnitName', 'optional'))
        ini.add_section(('policy_std', policy_section))
        
        crl_ext_section = []
        crl_ext_section.append(('authorityKeyIdentifier', 'keyid:always'))
        ini.add_section(('crl_ext', crl_ext_section))

        return ini
    
    @staticmethod
    def read_key(file_name, section, key):
        config = configparser.ConfigParser()
        
        res = config.read(file_name)
        if len(res) != 1:
            raise(SSLCAException(f'Unable to read key "{key}" in section "{section}" from config "{file_name}"'))
        
        return config.get(" " + section + " ", key)            
    
    def write(self, out_file_name):
        with open(out_file_name, "wb") as file:                
            for section in self.__sections:
                self.__write_section(section, file)


class Command:
    def __init__(self, command_string):
        self.command = command_string
        self.__help_string = ""
        #self.get_new_secret_func = lambda t: "e"
        #self.get_secret_func = lambda t: "e"
        self.get_new_secret_func = Command.type_new_secret
        self.get_secret_func = Command.type_existing_secret

    def recognize(self, args):
        if len(args) != 0:
            result = args[0] == self.command
        else:
            result = False
        
        return result

    @staticmethod
    def type_new_secret(type):
        pass1 = getpass.getpass(f'{type} Password: ')
        pass2 = getpass.getpass(f'{type} Password (verification): ')
        
        if pass1 != pass2:
            raise(SSLCAException('Passwords different. Aborting!'))
        
        return pass1

    @staticmethod
    def type_existing_secret(type):
        return getpass.getpass(f'{type} Password: ')

    @staticmethod    
    def print_exception(e):
        if 'MINICA_VERB' in os.environ.keys():
            traceback.print_exc()
        else:
            print(e)

    def process(self, args):
        result = ERR_OK
        
        try:
            self.proc_int(args)
        except Exception as e:
            Command.print_exception(e)
            result = ERR_NOT_OK
                
        return result
    
    @property
    def help_msg(self):
        return self.__help_string

    @help_msg.setter
    def help_msg(self, value):
        self.__help_string = value


class HelpCommand(Command):
    def __init__(self):
        super().__init__('help')
        self.commands = []
        self.help_msg = '       help This command has no options\n'
    
    def set_commands(self, command_list):
        self.commands = command_list
    
    def recognize(self, args):
        return True
    
    def process(self, args):
        help_message =  'minica <command> <options>\n'
        help_message += 'The following commands are allowed:\n'
        for i in self.commands:
            help_message += i.help_msg
        
        sys.stdout.write(help_message)
        return ERR_OK
    

class NewCommand(Command):
    def __init__(self):
        super().__init__('newca')
        self.help_msg = '       newca --ca <name> --org <orgname> --rootcert <filename>\n'

    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("minica newca command", "minica newca <options>", "Create a new CA with the specified name")
        parser.add_argument("-c", "--ca", required=True, help="Name of the new CA")
        parser.add_argument("-o", "--org", required=True, help="Organisation to use in root certificate")
        parser.add_argument("-r", "--rootcert", required=True, help="File into which a DER version of the root certificate is written")

        return parser.parse_args(args[1:])

    def __make_dir(self, dir_name, org_name):        
        os.mkdir(CA_HOME_DIRECTORY / dir_name, 0o700)
        os.mkdir(CA_HOME_DIRECTORY / dir_name / 'private', 0o700)
        os.mkdir(CA_HOME_DIRECTORY / dir_name / 'certs', 0o700)
        os.mkdir(CA_HOME_DIRECTORY / dir_name / 'crls', 0o700)
        os.mkdir(CA_HOME_DIRECTORY / dir_name / 'temp', 0o700)
        
        with open(CA_HOME_DIRECTORY / dir_name / 'private'/ 'serial.txt', "wb") as serial_number_file:
            serial_number_file.write('02\n'.encode('ascii'))

        with open(CA_HOME_DIRECTORY / dir_name / 'crls'/ 'crlnumber.txt', "wb") as crl_number_file:
            # The CRL number is in hex
            crl_number_file.write('1000\n'.encode('ascii'))

        with open(CA_HOME_DIRECTORY / dir_name  / 'private' / 'index.txt', "wb") as index_file:
            # simply create file
            pass
        
        ini = INIFile([])
        ca_ext_section = []
        ca_ext_section.append(('subjectKeyIdentifier', 'hash'))
        ca_ext_section.append(('authorityKeyIdentifier','keyid:always'))
        ca_ext_section.append(('basicConstraints', 'critical,CA:true'))
        ca_ext_section.append(('keyUsage', 'critical,cRLSign, keyCertSign'))
        ini.add_section(('ca_extensions', ca_ext_section))
        
        req_section = [('prompt', 'no'), ('distinguished_name', 'ca_dn')]
        ini.add_section(('req', req_section))
        
        dn_section = [('C', DEFAULT_COUNTRY), ('O', org_name), ('OU', 'CA'),('CN', dir_name)]
        ini.add_section(('ca_dn', dn_section))
        
        ini.write(CA_HOME_DIRECTORY / dir_name / 'private' / 'newca.cnf')
    
    def __make_root(self, dir_name, rootcert_filename):
        password = self.get_new_secret_func(SEC_TYPE_CA)     
        
        print('Generating CA private-key ....')

        ca_key_file = CA_HOME_DIRECTORY / dir_name / 'private' / 'CAkey.pem'
        ca_cert_file = CA_HOME_DIRECTORY / dir_name / 'private' / 'CAcert.pem'
        cfg_file = CA_HOME_DIRECTORY / dir_name / 'private' / 'newca.cnf'

        ret_code = os.system(f'openssl genrsa -out "{ca_key_file}" -passout "pass:{password}" -aes256 -f4 {CA_KEY_BITS}')
        if ret_code != 0:
            raise(SSLCAException('Unable to generate private CA Key'))
        
        print('Done!')        
        print('Creating root certificate ....')
                            
        serial = 1
        validity = ROOT_VALID_YEARS * 365
        
        exts = 'ca_extensions'
        cmd = f'openssl req -new -x509 -out "{ca_cert_file}" -key "{ca_key_file}" -days {validity} -set_serial {serial} -extensions {exts} -passin "pass:{password}" -config "{cfg_file}"'
        
        ret_code = os.system(cmd)
        if ret_code != 0:
            raise(SSLCAException('Unable to create root certificate'))
        
        print('Done!')
        print(f'Copying root certificte in DER format to "{rootcert_filename}"')
        
        cmd = f'openssl x509 -in "{ca_cert_file}" -outform DER -out "{rootcert_filename}"'        
        ret_code = os.system(cmd)
        if ret_code != 0:
            raise(SSLCAException('Unable to convert root cert to DER'))
        
        print('Done!')        

    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_dir(params.ca, params.org)
        self.__make_root(params.ca, params.rootcert)


class FileCleaner:
    def __init__(self, files_to_clean) -> None:
        self.files_to_clean = files_to_clean
    
    def clean(self):
        for i in self.files_to_clean:
            try:
                os.remove(i)
            except:
                pass


class OpenSSLCertIssuer:
    def __init__(self, ca_name, secret_getter):
        self.ca_name = ca_name
        self.write_pem = True
        self.split_pem = False
        self.common_names = []
        self.key_bits = SERVER_KEY_BITS
        self.org_name = ""
        self.extensions_section = ""
        self.include_cdp = False
        self.secret_getter = secret_getter

    def add_cdp(self, ext_section):
        if not self.include_cdp:
            return
        
        ext_section.append(('crlDistributionPoints', f'URI:{CDP_URL}'))

    def add_common_extensions(self, ext_section):
        ext_section.append(('subjectKeyIdentifier', 'hash'))
        ext_section.append(('authorityKeyIdentifier','keyid:always'))
        ext_section.append(('basicConstraints', 'critical,CA:FALSE'))
        self.add_cdp(ext_section)

    def issue_cert(self, key_file_out, pfx_file, ini_modifier):
        ca_cfg_file = CA_HOME_DIRECTORY / self.ca_name / 'private' / 'newca.cnf'
        cert_cfg_file = CA_HOME_DIRECTORY / self.ca_name / 'temp' / 'newcert.cnf'
        key_file = CA_HOME_DIRECTORY / self.ca_name / 'temp' / 'server.pem'
        p10_request_file = CA_HOME_DIRECTORY / self.ca_name / 'temp' / 'newcert.p10'
        cert_file = CA_HOME_DIRECTORY / self.ca_name / 'temp' / 'newcert.pem'
        
        cleaner = FileCleaner([cert_cfg_file, key_file, p10_request_file, cert_file])
        
        try:
            self.org_name = INIFile.read_key(ca_cfg_file, 'ca_dn', 'O')
                        
            ini = INIFile.get_std_sections(self.ca_name)
            ini = ini_modifier(ini, self)
            
            ini.write(cert_cfg_file)

            pass1 = self.secret_getter.get_secret_func(SEC_TYPE_CA)                        
            p12_pass1 = self.secret_getter.get_new_secret_func(SEC_TYPE_P12)
            
            print('Generating private-key ....')
            ret_code = os.system(f'openssl genrsa -out "{key_file}" -f4 {self.key_bits}')
            if ret_code != 0:
                raise(SSLCAException('Generating private-key failed'))
            
            print('Done!')        
            print('Creating certificate ....')
            
            cmd = f'openssl req -new -out "{p10_request_file}" -key "{key_file}" -config "{cert_cfg_file}"'
            ret_code = os.system(cmd)
            if ret_code != 0:
                raise(SSLCAException('Creating CSR failed failed'))
            
            cmd = f'openssl ca -notext -config "{cert_cfg_file}" -in "{p10_request_file}" -out "{cert_file}" -passin "pass:{pass1}" -extensions {self.extensions_section} -name CA_default -batch'
            ret_code = os.system(cmd)
            if ret_code != 0:
                raise(SSLCAException('Issuing certificate failed'))
                
            cmd = f'openssl pkcs12 -inkey "{key_file}" -in "{cert_file}" -export -password "pass:{p12_pass1}" -out {pfx_file}'
            ret_code = os.system(cmd)
            if ret_code != 0:
                raise(SSLCAException('Creating PFX file failed'))            
            
            print('Done!')
            
            if self.write_pem:
                if not self.split_pem:
                    with open(key_file, 'rb') as pri_key_f:
                        pri_key = pri_key_f.read()
                    
                    with open(cert_file, 'rb') as cert_f:
                        cert = cert_f.read()
                    
                    with open(key_file_out, 'wb') as res_f:
                        res_f.write(pri_key + cert)            
                else:
                    shutil.copyfile(key_file, f"{key_file_out}_key.pem")
                    shutil.copyfile(cert_file, f"{key_file_out}_crt.pem")
        finally:
            cleaner.clean()


class NewServerCommand(Command):
    def __init__(self):
        super().__init__('srvcrt')
        self.help_msg = '       srvcrt --ca <caname> --cn <name> [<name>, ...] --pem <pemfile> --pfx <pfxfile> [--cdp]\n'
    
    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("minica srvcrt command", "minica srvcrt <options>", "Create a new TLS server certificate")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")
        parser.add_argument("--cn", nargs='+', required=True,  help="Host names of the server")
        parser.add_argument("--pem", required=True, help="File into which the PEM version of the certificate is written")
        parser.add_argument("--pfx", required=True, help="File into which the PFX version of the certificate is written")
        parser.add_argument('--cdp', action='store_true', required=False, help="If present include CRL Distribution Point")
        parser.add_argument('--split', action='store_true', required=False, help="If present separate PEM files for cert and key are written")

        return parser.parse_args(args[1:])
    
    def __make_config(self, ini, issuer):
        issuer.extensions_section = 'server_extensions'

        server_ext_section = []
        issuer.add_common_extensions(server_ext_section)
        server_ext_section.append(('keyUsage', 'critical,digitalSignature, keyEncipherment, dataEncipherment'))
        server_ext_section.append(('extendedKeyUsage', 'serverAuth'))
        server_ext_section.append(('subjectAltName', '@alt_names'))
        ini.add_section((issuer.extensions_section, server_ext_section))            
        
        alt_names_section = []
        count = 0
        for i in issuer.common_names:  
            alt_names_section.append((f"DNS.{count}", i))
            count += 1
        
        ini.add_section(('alt_names', alt_names_section))
        
        req_section = [('prompt', 'no'), ('distinguished_name', 'server_dn')]
        ini.add_section(('req', req_section))
        
        dn_section = [('C', DEFAULT_COUNTRY), ('O', issuer.org_name), ('CN', issuer.common_names[0])]
        ini.add_section(('server_dn', dn_section))

        return ini        

    def __make_server_cert(self, ca_name, common_names, key_file_out, pfx_file, cdp, split_pem):
        issuer = OpenSSLCertIssuer(ca_name, self)
        issuer.common_names = common_names
        issuer.key_bits = SERVER_KEY_BITS
        issuer.include_cdp = cdp
        issuer.split_pem = split_pem
        issuer.issue_cert(key_file_out, pfx_file, self.__make_config)

    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_server_cert(params.ca, params.cn, params.pem, params.pfx, params.cdp, params.split)


class NewClientCommand(Command):
    def __init__(self):
        super().__init__('clientcrt')
        self.help_msg = '       clientcrt --ca <caname> --cn <name> --pfx <pfxfile> [--cdp]\n'

    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("OpenSSL CA clientcrt command", "minica clientcrt <options>", "Create a new certificate for TLS client authentication")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")
        parser.add_argument("--cn", required=True, help="CommonName which is to be used to create the client certificate")
        parser.add_argument("--pfx", required=True, help="File into which the created certificate is written in PFX format")
        parser.add_argument('--cdp', action='store_true', required=False, help="If present include CRL Distribution Point")

        return parser.parse_args(args[1:])
    
    def __make_config(self, ini, issuer):
        issuer.extensions_section = 'client_extensions'

        client_ext_section = []
        issuer.add_common_extensions(client_ext_section)
        client_ext_section.append(('keyUsage', 'critical,digitalSignature'))
        client_ext_section.append(('extendedKeyUsage', 'clientAuth'))
        ini.add_section((issuer.extensions_section, client_ext_section))
        
        req_section = [('prompt', 'no'), ('distinguished_name', 'client_dn')]
        ini.add_section(('req', req_section))
        
        dn_section = [('C', DEFAULT_COUNTRY), ('O', issuer.org_name), ('CN', issuer.common_names[0])]
        ini.add_section(('client_dn', dn_section))

        return ini 

    def __make_client_cert(self, ca_name, common_name, p12_file_name, cdp):
        issuer = OpenSSLCertIssuer(ca_name, self)
        issuer.key_bits = CLIENT_KEY_BITS
        issuer.common_names = [common_name]
        issuer.write_pem = False
        issuer.include_cdp = cdp
        issuer.issue_cert("", p12_file_name, self.__make_config)

    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_client_cert(params.ca, params.cn, params.pfx, params.cdp)


class NewMailCommand(Command):
    def __init__(self):
        super().__init__('mailcrt')
        self.help_msg = '       mailcrt --ca <caname> --cn <name> --mail <mail address> --type <encauth|enc|auth> --pfx <pfxfile> [--cdp]\n'

    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("OpenSSL CA mailcrt command", "minica mailcrt <options>", "Create a new S/MIME certificate")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")
        parser.add_argument("--cn", required=True, help="CommonName which is to be used to create the certificate")
        parser.add_argument("--pfx", required=True, help="File into which the created certificate is written in PFX format")
        parser.add_argument("--mail", required=True, help="Mail address which is to be used to create the certificate")
        parser.add_argument("--type", choices=['encauth', 'enc', 'auth'], required=True, help="Type of KeyUsage to use in the certificate")
        parser.add_argument('--cdp', action='store_true', required=False, help="If present include CRL Distribution Point")

        return parser.parse_args(args[1:])
    
    def __make_config(self, ini, issuer):
        mail_ext_section = []
        issuer.add_common_extensions(mail_ext_section)
        
        if issuer.cert_type == 'encauth':
            mail_ext_section.append(('keyUsage', 'critical,digitalSignature,dataEncipherment,keyEncipherment'))            
        elif issuer.cert_type == 'enc':
            mail_ext_section.append(('keyUsage', 'critical,dataEncipherment,keyEncipherment'))
        else:
            mail_ext_section.append(('keyUsage', 'critical,digitalSignature'))            
                
        mail_ext_section.append(('subjectAltName',f'email:{issuer.mailaddress}'))
        mail_ext_section.append(('extendedKeyUsage', 'emailProtection'))

        issuer.extensions_section = 'mail_extensions'
        ini.add_section((issuer.extensions_section, mail_ext_section))
        
        req_section = [('prompt', 'no'), ('distinguished_name', 'mail_dn')]
        ini.add_section(('req', req_section))
        
        dn_section = [('C', DEFAULT_COUNTRY), ('O', issuer.org_name), ('CN', issuer.common_names[0]), ('OU', issuer.org_unit), ('emailAddress', issuer.mailaddress)]
        ini.add_section(('mail_dn', dn_section))

        return ini

    def __make_mail_cert(self, ca_name, common_name, mailaddress, cert_type, p12_file_name, cdp):
        issuer = OpenSSLCertIssuer(ca_name, self)
        issuer.common_names = [common_name]
        issuer.write_pem = False
        issuer.key_bits = MAIL_KEY_BITS
        issuer.mailaddress = mailaddress
        issuer.cert_type = cert_type
        issuer.org_unit = DEFAULT_OU
        issuer.include_cdp = cdp
        issuer.issue_cert("", p12_file_name, self.__make_config)

    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_mail_cert(params.ca, params.cn, params.mail, params.type, params.pfx, params.cdp)


class MakeCRLCommand(Command):
    def __init__(self):
        super().__init__('crl')
        self.help_msg = '       crl --ca <caname>\n'
    
    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("OpenSSL CA create  CRL command", "minica crl <options>", "Create a new CRL for the CA")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")

        return parser.parse_args(args[1:])
    
    def __make_crl(self, ca_name):
        ca_cfg_file = CA_HOME_DIRECTORY / ca_name / 'temp' / 'ca.cnf'
        
        cleaner = FileCleaner([ca_cfg_file])
        
        try:
            ini = INIFile.get_std_sections(ca_name)                        
            ini.write(ca_cfg_file)            
            pass1 = self.get_secret_func(SEC_TYPE_CA)
                        
            print('Generating CRL ....')

            ret_code = os.system(f'openssl ca -config "{ca_cfg_file}" -passin "pass:{pass1}" -name CA_default -gencrl -out crl.pem')
            if ret_code != 0:
                raise(SSLCAException('Generating CRL failed'))
            
            print('Done!')                        
        finally:
            cleaner.clean()
    
    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_crl(params.ca)


class MakeRevokeCommand(Command):
    def __init__(self):
        super().__init__('revoke')
        self.help_msg = '       revoke --ca <caname> --serial <serial number of cert to revoke>\n'

    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("OpenSSL CA revoke command", "minica revoke <options>", "Revoke a certificate with a given serial number. The serial number can be determined through the list command.")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")
        parser.add_argument("--serial", required=True, help="Serial number of certificate to revoke")

        return parser.parse_args(args[1:])
    
    def __make_revoke(self, ca_name, certfile):
        ca_config_file = CA_HOME_DIRECTORY / ca_name / 'temp' / 'ca.cnf'
        created_files = [ca_config_file]
        
        cleaner = FileCleaner(created_files)

        try:
            ini = INIFile.get_std_sections(ca_name)   
            ini.write(ca_config_file)            
            pass1 = self.get_secret_func(SEC_TYPE_CA)
                        
            print('Revoking cert ....')
            cert_file_to_revoke = CA_HOME_DIRECTORY / ca_name / 'certs' / f"{certfile}.pem"

            ret_code = os.system(f'openssl ca -config "{ca_config_file}" -name CA_default -passin "pass:{pass1}" -revoke "{cert_file_to_revoke}"')
            if ret_code != 0:
                raise(SSLCAException(f'Revocation of cert "{cert_file_to_revoke}" failed'))
            
            print('Done!')   
        finally:
            cleaner.clean()
    
    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_revoke(params.ca, params.serial)


class ShowCommand(Command):
    def __init__(self):
        super().__init__('show')
        self.help_msg = '       show --ca <caname> --serial <cert_to_revoke>\n'

    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("OpenSSL CA show command", "minica show <options>", "Show/parse certificate with given serial number. The serial number can be determined through the list command.")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")
        parser.add_argument("--serial", required=True, help="Serial number of certificate to revoke")

        return parser.parse_args(args[1:])

    def __make_show(self, ca_name, certfile):
        cert_file_to_show = CA_HOME_DIRECTORY / ca_name / 'certs' / f"{certfile}.pem"

        ret_code = os.system(f'openssl x509 -in "{cert_file_to_show}" -text')
        if ret_code != 0:
            raise(SSLCAException(f'Parsing cert "{cert_file_to_show}" failed'))

    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_show(params.ca, params.serial)


class ListCommand(Command):
    def __init__(self):
        super().__init__('list')
        self.help_msg = '       list --ca <caname>\n'

    def __parse_args_alt(self, args):
        parser = argparse.ArgumentParser("OpenSSL CA list certificates command", "minica list <options>", "List certificate database of CA")
        parser.add_argument("-c", "--ca", required=True, help="Name of the CA")

        return parser.parse_args(args[1:])

    def __make_list(self, ca_name):
        ca_index_file = CA_HOME_DIRECTORY / ca_name / 'private' / 'index.txt'
        
        with open(ca_index_file, "r") as f:
            lines = f.readlines()
        
        for i in lines:
            sys.stdout.write(i)

    def proc_int(self, args):
        params = self.__parse_args_alt(args)
        self.__make_list(params.ca)


def main(argv):
    exit_code = 0
    help = HelpCommand()
    
    commands = [NewCommand(), NewClientCommand(), NewServerCommand(), NewMailCommand(), MakeCRLCommand(), MakeRevokeCommand(), ListCommand(), ShowCommand(), help]
    help.set_commands(commands)
    
    if len(argv) == 1:
        exit_code = help.process(argv)
    else:
        command_line = argv[1:]
        for i in commands:
            if i.recognize(command_line) == True:
                exit_code = i.process(command_line)
                break
    
    sys.exit(exit_code)

main(sys.argv)
