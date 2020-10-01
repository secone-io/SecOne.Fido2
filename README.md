# SecOne.Fido2

Based on https://github.com/borrrden/Fido2Net. 

Adds support for SecureString marshalling to the underlying Yubikey APIs for PIN values.

This is a set of .NET classes and bindings for wrapping the [libfido2](https://github.com/Yubico/libfido2) implementation. Requires the dlls from https://developers.yubico.com/libfido2/Releases/


## Main API

### `FidoAssertion`

This class is responsible for handling the **assertion** portion of the FIDO2 logic.  That is to say, a credential has already been created and a remote party would like to validate that the user is in control of said credential.  

### `FidoCredential`

This class is what gets created during the **attestation** portion of the FIDO2 logic, and what is used during the **assertion** portion.

### `FidoDevice`

This class abstracts a FIDO2 capable device and lets you interact with it.  It is responsible for credential and assertion creation (see its usage in the `FidoAssertion` and `FidoCredential` examples)

### `FidoDeviceInfoList`

This class will enumerate attached FIDO2 devices for you


## Samples

See the Examples directory

