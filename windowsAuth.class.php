<?php

/**
 * windowsAuth.class.php
 *
 * Get Windows Credentials from a IIS server and a client connected through Active Directory
 * Natively supported by IE & Chrome on Windows. For others, a user/password prompt will display
 *
 * @category   Authentication
 * @package    IIS
 * @author     Charles Bourgeaux
 * @copyright  2016 Charles Bourgeaux - Maecia
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    1.0.0
 * @link       https://github.com/charlyie/windows-credentials-active-directory.git
 */

Class WindowsAuth {
    public  $authenticationMethod   = null;
    public  $domain                 = null;
    public  $user                   = null;
    private $authenticationOffset   = null;
    private $authorizationToken     = null;
    public  $initialized            = false;
    public  $errors                 = array();


    /**
    * Determines if the user's environment is compatible (Windows and chrome/IE browser)
    *
    * @param    <none>
    * @return   (boolean) true if environment is compatible
    */
    private function isCompatibleEnvironment() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        if (preg_match('/windows|win32/i', $userAgent) AND (preg_match('/MSIE/i', $userAgent) OR ( preg_match('/Windows NT/i', $userAgent) AND preg_match('/Trident/i', $userAgent)) OR preg_match('/Chrome/i', $userAgent)))
            return true;
        else
            return false;   
    }


    /**
    * Check user's headers and determine Authentication method
    *
    * @param    <none>
    * @return   <none>
    */
    private function checkHeaders() {

        $clientHeaders = apache_request_headers();
        // NTLM does not work through a proxy
        if( @$_SERVER['HTTP_VIA'] != NULL ) { 
            $this->declareError('101', 'Windows authentication cannot work through a proxy.');
            return false;
        } 
        
        //if authorization header does not exist, throw to the client a 401 ERROR
        if( !isset($clientHeaders['Authorization']) ) { 
            $this->declareError('102', 'Authorization entry not found in client headers.');
            $this->sendUnauthorizedAccess();
        }

        $this->authorizationToken = $clientHeaders['Authorization'];

        if( substr($this->authorizationToken, 0, 5) == 'NTLM ' ){
            $this->authenticationMethod = 'NTLM';
            $this->authenticationOffset = 5;
        }
        if( substr($this->authorizationToken, 0, 10) == 'Negotiate ') {
            $this->authenticationMethod = 'NEGOTIATE';
            $this->authenticationOffset = 10;
        }
    }


    /**
    * Retrieve user from authentication
    *
    * @param    <none>
    * @return   $user (string) login
    */
    public function getUser() {
        if( !$this->authenticationMethod )
            $this->getCredentials();

        return $this->user;
    }


    /**
    * Retrieve domain from authentication
    *
    * @param    <none>
    * @return   $domain (string) Active Directory domain
    */
    public function getDomain() {
        if( !$this->authenticationMethod )
            $this->getCredentials();
        return $this->domain;
    }


    /**
    * Provides user's credentials
    *
    * @param    <none>
    * @return   (boolean|instanceof(WindowsAuth)) boolean if false or the complete object
    */
    public function getCredentials() {
        $this->initialized = true;
        if( !$this->isCompatibleEnvironment() )
            $this->declareError('100', 'Complete authentication can be provided only on Windows environments and for Chrome or Internet Explorer.');

        $this->checkHeaders();
        if( !$this->authenticationMethod ){
            $this->declareError('103', 'Unknown authentication method. Should be NTLM or Negociate (Kerberos).');
            return false;
        }
            
     
        $token64 = base64_decode(substr($this->authorizationToken, $this->authenticationOffset)); // get Base64-encoded type1 message
        if( ord($token64{8}) == 1 ) {
            $retAuth = "NTLMSSP" . chr(000) . chr(002) . chr(000) . chr(000) . chr(000) . chr(000) . chr(000) . chr(000);
            $retAuth .= chr(000) . chr(040) . chr(000) . chr(000) . chr(000) . chr(001) . chr(130) . chr(000) . chr(000);
            $retAuth .= chr(000) . chr(002) . chr(002) . chr(002) . chr(000) . chr(000) . chr(000) . chr(000) . chr(000);
            $retAuth .= chr(000) . chr(000) . chr(000) . chr(000) . chr(000) . chr(000) . chr(000);
            $retAuth64 = base64_encode($retAuth); 
            $retAuth64 = trim($retAuth64); 
            $this->declareError('104', 'Authentication needs further informations.');
            header("HTTP/1.1 401 Unauthorized"); // send new header
            header("WWW-Authenticate: NTLM $retAuth64"); // need additionnal authentication
            exit;
        } else if( ord($token64{8}) == 3 ) {
            $lenght_domain = (ord($token64[31]) * 256 + ord($token64[30])); // domain length
            $offset_domain = (ord($token64[33]) * 256 + ord($token64[32])); // domain position
            $this->domain = str_replace("\0", "", substr($token64, $offset_domain, $lenght_domain)); // extracting domain
     
            $lenght_login = (ord($token64[39]) * 256 + ord($token64[38])); // user length
            $offset_login = (ord($token64[41]) * 256 + ord($token64[40])); // user position
            $this->user = str_replace("\0", "", substr($token64, $offset_login, $lenght_login)); // extracting user

            if( empty($this->domain) ) {
                $this->declareError('105', 'Cannot guess Active Directory Domain. Maybe a bad environment (OS/Browser) ?');
            }
            if( !empty($this->user) ) {
                return $this;
            }
            
        }
        $this->declareError('106', 'Cannot decode properly authorization token');
        return false;
    }


    /**
    * Return to the user an unauthorized system page
    *
    * @param    <none>
    * @return   <none>
    */
    private function sendUnauthorizedAccess() {
        header("HTTP/1.1 401 Unauthorized");
        header("Connection: Keep-Alive");
        header("WWW-Authenticate: Negotiate");
        header("WWW-Authenticate: NTLM");
        exit;
    }


    /**
    * Internal use : for error declaration purposes
    *
    * @param    $code (string) error code
    * @param    $description (string) error description
    * @return   <none>
    */
    public function declareError( $code, $description ) {
        $this->errors[] = array('code' => $code, 'long' => $description);
    }


    /**
    * Internal use : to display errors
    *
    * @param    $format (string) must be 'array' or 'string'
    * @return   (boolean|array|string) declaration output
    */
    public function getErrors( $format = 'array') {
        if( !$this->initialized)
            $this->declareError('001', 'getCredentials or getUser methods have to be launched BEFORE error detection');
        if( sizeof($this->errors) == 0 )
            return false;

        if($format == 'array')
            return $this->errors;


        $str = null;
        foreach($this->errors as $e) {
            $str .= 'Error #' . $e['code'] . ' : ' . $e['long'] . "<br>";
        }
        return $str;
    }
}
