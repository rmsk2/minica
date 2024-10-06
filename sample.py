import minica
import base64
import secrets

CA_NAME = "Test CA"
CA_ORG = "Test Org"


def new_secret(type):
    global CA_PW

    if type == minica.SEC_TYPE_CA:
        CA_PW = minica.SecretGetterRepo.type_new_secret(type)
        return CA_PW
    else:
        raw = secrets.token_bytes(12)
        pw_b = base64.b64encode(raw, b"!$")
        pw = pw_b.decode('ascii')
        print(f"PFX password: {pw}")
        return pw


def existing_secret(type):
    return CA_PW


def divider():
    print("----------------------------------------------------------------------------------------")    


try:
    minica.REPO.use_new_getters("auto", existing_secret, new_secret)
    minica.set_ca_dir("./")
    minica.CDP_URL = 'http://crl.test.com/test-ca.crl'

    generator = minica.NewCommand()
    server_issuer = minica.NewServerCommand()
    revoker = minica.MakeRevokeCommand()
    # Suppress textual output for this command by setting print_messages to False in
    # constructor
    crl = minica.MakeCRLCommand(False)

    divider()
    generator.make_new(CA_NAME, CA_ORG, f"{CA_NAME}_root.crt")

    divider()    
    server_issuer.make_server_cert(CA_NAME, ["server1", "server1.test.com"], "server1", "server1.pfx", True, True)    
    
    divider()
    server_issuer.make_server_cert(CA_NAME, ["server2.test.conm"], "server2", "server2.pfx", False, True)
    
    divider()
    server_issuer.make_server_cert(CA_NAME, ["revoke.test.com", "revoke"], "revoke", "revoke.pfx", False, True)

    divider()
    revoker.make_revoke(CA_NAME, "04")

    divider()
    crl.make_crl(CA_NAME, "test-ca.crl")

except Exception as e:
    print(e)