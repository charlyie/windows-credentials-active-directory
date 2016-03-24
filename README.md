# Get Windows Credentials from PHP
*PHP class which allow the user to get Windows current login*

## Environment ##
**Server** : must run on IIS with Authentication enabled to "Windows Authentication" (NTLM or Negociate (Kerberos/Negociate))
**Client** : Should be Internet Explorer or Google Chrome. Works with other browser by prompting user/password

## Use case ##
`require 'windowsAuth.class.php';`

`$windowsAuth = new WindowsAuth();`

`echo "User : " . $windowsAuth->getUser();`

`echo "Domain : " . $windowsAuth->getDomain();`

`echo $windowsAuth->getErrors('string');`
