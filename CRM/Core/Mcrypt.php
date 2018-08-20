<?php
/**
 * Created by IntelliJ IDEA.
 * User: emcnaughton
 * Date: 8/20/18
 * Time: 6:35 PM
 */
class CRM_Core_Mcrypt implements CRM_Core_Encrypt_Interface {

  /**
   * Encrypts a string.
   *
   * @param string $string
   *   Plaintext to be encrypted.
   * @return string
   *   ciphertext
   */
  public function encrypt($string) {
    if (function_exists('mcrypt_module_open') &&
      defined('CIVICRM_SITE_KEY')
    ) {
      $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_ECB, '');
      // ECB mode - iv not needed - CRM-8198
      $iv = '00000000000000000000000000000000';
      $ks = mcrypt_enc_get_key_size($td);
      $key = substr(sha1(CIVICRM_SITE_KEY), 0, $ks);

      mcrypt_generic_init($td, $key, $iv);
      $string = mcrypt_generic($td, $string);
      mcrypt_generic_deinit($td);
      mcrypt_module_close($td);
    }
    return $string;
  }

  /**
   * Decrypts ciphertext.
   *
   * @param string $string
   *   Ciphertext to be decrypted.
   * @return string
   *   Plaintext
   */
  public function decrypt($string) {
    if (function_exists('mcrypt_module_open') &&
      defined('CIVICRM_SITE_KEY')
    ) {
      $td = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_ECB, '');
      // ECB mode - iv not needed - CRM-8198
      $iv = '00000000000000000000000000000000';
      $ks = mcrypt_enc_get_key_size($td);
      $key = substr(sha1(CIVICRM_SITE_KEY), 0, $ks);

      mcrypt_generic_init($td, $key, $iv);
      $string = rtrim(mdecrypt_generic($td, $string));
      mcrypt_generic_deinit($td);
      mcrypt_module_close($td);
    }
    return $string;
  }
}