# minica

A Python script that allows you to run a mini CA based on OpenSSL. This in turn has the consequence
that OpenSSL has to be installed  on your system, and it has to be in the path of the user who is calling `minica`.
One can use `minica` as a command line program or directly in Python code after a corresponding `import minica`. 
It is intended for issuing certificates in a home or lab setting and is not suitable for large deployments.
Consequently in order to keep things simple the root cert is used to issue end entity certificates without 
an intermediate CA. At the moment `minica` only supports RSA.

**Remark**: If the  version of `minica` you use does not have a `version` command please update to the latest version
and read the section which can be found [here](#a-bug-in-password-processing).

# The command line interface

`minica` implements several commands which in turn require certain options. Here a summary of all the commands and
their options:

```
minica <command> <options>
The following commands are allowed:
       new --ca <name> --org <orgname> [--rootcert <filename>]
       clientcrt --ca <caname> --cn <name> --pfx <pfxfile> [--cdp]
       srvcrt --ca <caname> --cn <name> [<name>, ...] --pem <pemfile> --pfx <pfxfile> [--cdp] [--split]
       mailcrt --ca <caname> --cn <name> --mail <mail address> --type <encauth|enc|auth> --pfx <pfxfile> [--cdp]
       crl --ca <caname>
       revoke --ca <caname> --serial <serial number of cert to revoke>
       list --ca <caname>
       show --ca <caname> --serial <serial number of cert to show>
       pwchange --ca <caname>
       version The version command has no options
       help The help command has no options
```

Before a CA can be used to issue certificates it has to be created via the `new` command. This command creates a 
new subdirectory in  the CA base directory. See below how to determine the base directory. This directory can
contain subdirectories for serveral CAs. The name of the CA subdirectory is derived from the value used with
the `--ca` option. When the option `--rootcert` is present a DER encoded version of the newly created root certificate 
is copied to the specified file. It can then be used to configure the trust settings of browsers or other software.

The three commands `srvcrt`, `mailcrt` and `clientcrt` can be used to issue TLS server, S/MIME oder TLS client certificates.
A server certificate can contain several SANs as specified by the `--cn` option. If the `--cdp` option is present a
`CRLDistributionPoint` Extension is included in the certificate which points browsers or other software to a HTTP URL 
where a Certificate Revocation List of the CA can be found (see below on how to set this URL and how to create a CRL). 

When a server certificate is created the certificate and its corresponding private RSA-key will not only be
returned in PKCS#12 or PFX format but also in PEM format. When the option `--split` is present, then separate
PEM files are created for the certificate and the key. The names of both files are derived from the value of the `--pem`
option. If `--split` is not given private key and certificate are appended to each other and stored in the same file.

Certificates which are intended for S/MIME can be issued via the `mailcrt` command. The `--type` option can be used to define
whether the new certificate can be utilized to only sign (type `auth`) or encrypt mails (type `enc` ) or for both
purposes (type `encauth`).

The `crl` command offers the possibility to create a new CRL for the CA. A CRL lists all the certificates which have been
revoked via the `revoke` command. During a revocation the certificate serial number of the certificate which is to be
invalidated has to be specified via the `--serial` option. This serial number has to be identical to the serial number 
of the certificate as printed by the `list` command. An example

```
V	251004154646Z		02	unknown	/C=DE/O=Daheim/CN=xxxxxxxxxx
V	251004154646Z		03	unknown	/C=DE/O=Daheim/CN=xxxxxxxxxx
V	251004154647Z		04	unknown	/C=DE/O=Daheim/CN=xxxxxxxxxx
```

The serial numbers used in a revocation would be `02`, `03` or `04`. Finally the `show` command offers the possibility 
to look at a parsed version of the certificate specified by its serial number, where the serial number is determined in 
the same way as illustrated above.

# Example: Generating a CA, a server and a client certificate

Let's say we want to create a new CA with the common name `Private TLS CA` and the organisation name `At home` in the
directory into which `minica` was cloned. As a first step we would issue the following command:

```
python3 minica.py new --ca "Private TLS CA" --org "At home" --rootcert private_root.crt
```

which creates the CA subdirectory `Private TLS CA` in the `CADATA` folder, generates a 4096 bit RSA key pair and stores the
newly created root certificate in DER format in the file `private_root.crt`. The certificate is valid for five years.
Let's further assume we want to create a TLS server certificate for the machine `testerver.athome.com` which is also known as 
`testserver`. For that we would use the command

```
python3 minica.py srvcrt --ca "Private TLS CA" --cn testserver.athome.com testserver --pem testserver --split --pfx testserver.pfx
```

This creates a new 3072 bit RSA key pair as well as the files `testserver_key.pem`, `testserver_crt.pem` and `testserver.pfx`. The 
PEM  files or alternatively the PFX file can be used to configure your webserver. The new server certificate has a validity period of 
one year and two SANs. Finally we could create a TLS client certificate for mTLS. This can be achieved via the command

```
python3 minica.py clientcrt --ca "Private TLS CA" --cn Testuser --pfx testuser.pfx
```

The client certificate can then be found in the file `testuser.pfx` and is also valid for one year. If you want to customize the 
defaults for key lengths, validity periods or other behaviour see below.

# Customizing the behaviour of `minica`

The following defaults are defined in the script. Please change them to suit your needs:

```py
# Change here to suit your needs
###############################################
#
# certificate and CRL contents
#
CA_KEY_BITS = 4096
SERVER_KEY_BITS = 3072
CLIENT_KEY_BITS = 3072
MAIL_KEY_BITS = 3072
END_ENTITY_VALID_DAYS = 365
ROOT_VALID_YEARS = 5
ROOT_SERIAL = 1
CRL_VALID_DAYS = 30
DEFAULT_COUNTRY = 'DE'
DEFAULT_OU = 'Users'
DEFAULT_HASH = 'sha256'
CDP_URL = 'http://test/ca/crl.crl'
#
# Program config
#
CA_BASE_DIR = './CADATA/'
# Name of optional environment variable which specifies path to base dir if set
CA_ENV = 'MINICA_DIR'
SHOW_OPENSSL_OUTPUT = False
SHOW_PROG_OUTPUT = True
###############################################
```

Additionally the following environment variables can be set in order to influence the behaviour of `minica`. If the variable
`MINICA_VERB` is set to a value then the full stack trace of exceptions is propagated and printed to the command line, which
can be useful to diagnose problems. The variable `MINICA_DIR` can be used to override the value of `CA_BASE_DIR` during 
runtime. If you uncomment the line

```
#REPO.use_new_getters("auto", alternate_existing_secret, alternate_new_secret)
```

at the end of `minica.py` then `minica` creates the PFX passwords for all end entity certificates for you and prints them to the 
console.

# Using `minica` in Python code

When you want to use `minica.py` in other Python scripts you can import it via `import minica`. For each of the commands mentioned
above you will find a corresponding class in the code, which can be instantiated and then called accordingly. 

## Suppressing textual output

In the constructor of each command class you can define whether calling the `make_....`  method of the class prints anything to the console
or not. A boolean value of `False` suppresses all output. When simply automating certain tasks this output may be useful but it is a potential
distraction in more complicated code. The default for this value can be found in the global variable `SHOW_PROG_OUTPUT`. The global variable
`SHOW_OPENSSL_OUTPUT` is intended to allow the output generated by OpenSSL to be viewed by the user or not. The default is set to not 
show the messages generated by OpenSSL.

## Manually setting the CA base directory

The function `minica.set_ca_dir()` can be used to override the previously set value for the CA base directory. Calling this function
also overrides a value deduced from a potentially set `MINICA_DIR` environment variable.

## Automating password entry

Passwords are used by `minica` to encrypt the private keys of the CA and of newly generated end entitiy certificates. The default
behaviour is to the let the user type in new or previously set passwords. This can be a problem when automating certificate issuance
during tests or similar tasks. It is therefore easy to change this behavior. The global variable `minica.REPO` contains a repository which
manages a set of alternative functions for secret retrieval. There are functions to retrieve existing passwords and new passwords.
Additionally there are two types of passwords `minica.SEC_TYPE_CA` and `minica.SEC_TYPE_P12`. The first type is intended 
for encryption of the private key of the CA and the second one signifies that a password is to be used for encryption of end entity private
keys.

Through the function call `minica.REPO.use_new_getters("id", existing_secret_function, new_secret_function)` a new set of secret retrieval
functions can be activated. The first parameter can be set to any value which makes sense in your scenario. The second parameter has to contain
a function which is called when a previosly set password is needed again. The third parameter has to specifiy a function which generates
a new password. Setting the property  `minica.REPO.current` lets you change between different sets of secret retrieval functions as
specified by their ids. The default value of `minica.REPO.current` is `default`.

Here an example which shows how to make use of alternative secret retrieval functions. In this example (see `new_secret()`) the user has to 
type in a new CA password while generating the root certificate. The passwords for new end entity certificates are generated automatically. 
After inital manual entry of the CA password it is subsequently returned without manual intervention (see `existing_secret()`):

```py
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


minica.REPO.use_new_getters("auto", existing_secret, new_secret)
```

The `existing_secret()` function does not distinguish between `SEC_TYPE_CA` and `SEC_TYPE_P12` passwords as `minica` never needs to call the 
secret retrieval function for existing PKCS#12 passwords when issuing a certificate. Have a look at `sample.py` for a script which generates
a new CA, issues three TLS certificates using this CA, revokes one of the certs and creates a CRL.

# A bug in password processing

All published revisions beginning with commit [4389afa](https://github.com/rmsk2/minica/commit/4389afabbf7a307b7d027ebfe10dbbb25fb8813a) 
and before commit [add4d86](https://github.com/rmsk2/minica/commit/add4d866446674f0aad28cd522888bd10aedc827) 
suffered from a bug which caused all passwords to be set to the string `None`. Commit add4d86 fixed the bug and was created on 05 october 2024. 
The repo was made public only one day before that date. So, given the low volume of traffic that this repo experiences, it is essence very 
unlikely that you (or in fact anyone) was affected by this problem. Nontheless if you were you can use `minica pwchange` to change the CA 
private key password to a proper value. 

You additionally can use the command `openssl pkcs12 -in cert.pfx > cert.pem` follwowed by 
`openssl pkcs12 -in cert.pem -inkey cert.pem -out cert_new.pfx -export` to reencrypt affected PKCS#12 key stores. On the other hand 
if you tried to import such a PFX-file into a browser or other software the problem became apparent as the password which
was assumed to be correct would not work.

The problem was difficult to spot, because the bug only changed the expected behaviour of `minica` when one knowningly entered a wrong 
password. 

This bug was caused by missing `return` statements in `Command.get_new_secret_func()` and `Command.get_secret_func()`. These
functions were introduced in commit [6695e31](https://github.com/rmsk2/minica/commit/6695e31044862a7acba72233101215b2f5d282f7) 
and last modified in commit [dba1217](https://github.com/rmsk2/minica/commit/dba1217015a7d27f88e812b1d23148ca8402839d) when
the repo was still private. As a consequence calling functions, which expected a return value (i.e. here a password), simply got the value 
`None` which was converted to the string `"None"` in string interpolations. 

